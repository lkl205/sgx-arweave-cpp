#include "listen_svr.h"
#include "msg_handler.h"
#include "../common/log_u.h"
#include <cpprest/http_client.h>
#include <safeheron/crypto-bn/bn.h>
#include <safeheron/crypto-bn/rand.h>

using namespace utility;
using namespace web::http;
using namespace web::http::client;
using safeheron::bignum::BN;
#开机启动，等待别人发请求
#收到post/generate或/query
#请求丢给msg_handler处理
#处理完，用webhook发给客户端结果
/**
 * @brief This is a timer thread, use to release stopped 
 *        threads in msg_handler::s_thread_pool.
 * 
 * @param param a listen_svr objects
 * @return int 
 */
static int timer_thread_func( void* param )
{
    int timer_interval = 10; // 每10秒跑一次
    listen_svr* svr = (listen_svr*)param;

    if ( !svr ) return -1;

    do {
        for (int i = 0; i < timer_interval; i++) {
            // 每10秒清理一次off的线程
            if ( svr->is_stopping_ ) goto _exit;
            sleep( 1 );
        }
        // Check msg_handler::s_thread_pool, and release stopped threads
        msg_handler::ReleaseStoppedThreads();
    }while (1);

_exit:   
    return 0;
}

// The HTTP listen server class
listen_svr::listen_svr( const std::string & url )
 : listener_( url )
 , timer_thread_( nullptr )
 , is_stopping_( false )
{
    listener_.support(methods::POST, 
                      std::bind(&listen_svr::HandleMessage, 
                      this, 
                      std::placeholders::_1));
    listener_.support(methods::GET, 
                      std::bind(&listen_svr::HandleMessage, 
                      this, 
                      std::placeholders::_1));
}//启动一个http服务，等待接收post（生成密钥/查询）和get请求

listen_svr::~listen_svr()
{
}

// Start listening
pplx::task<void> listen_svr::open() 
{ 
    int ret = 0;

    // free old object
    if ( timer_thread_ ) {
        is_stopping_ = true;
        timer_thread_->stop();
        delete timer_thread_;
        timer_thread_ = nullptr;
    }
    //启动服务，打开http端口，开始监听客户端请求
    // start the timer thread to check msg_handler::s_thread_pool
    is_stopping_ = false;
    timer_thread_ = new ThreadTask( timer_thread_func, this );
    timer_thread_->start();

    return listener_.open(); 
}

// Stop listening
pplx::task<void> listen_svr::close() 
{
    // stop timer thread at first
    if ( timer_thread_ ) {
        is_stopping_ = true;
        timer_thread_->stop();
        delete timer_thread_;
        timer_thread_ = nullptr;
    }
//关闭服务
    // clean msg_handler::s_thread_pool
    msg_handler::DestroyThreadPool();

    return listener_.close(); 
}

// An HTTP request message is received
void listen_svr::HandleMessage( const http_request & message )
{
//1、拿到请求路径：/generate或/query
    std::string request_id;//2、生成一个唯一请求ID(方便日志追踪)
    std::string path = message.request_uri().path();//3、交给msg_handler处理
    auto req_body = message.extract_json().get();

    FUNC_BEGIN;

    // Generate an unique ID for the log of each HTTP request
    request_id = CreateRequestID();
    INFO_OUTPUT_CONSOLE( "Request ID: %s is received!", request_id.c_str() );

    if ( path.length() == 0 ) {
        ERROR( "Request ID: %s, path is null!", request_id.c_str() );
        message.reply( status_codes::BadRequest, "Unknown request path!" );
    }

    // Process the request and reply with the corresponding response to callback address
    msg_handler handler;
    std::string resp_body;
    handler.process( request_id, path, req_body.serialize(), resp_body );
    web::json::value resp_json = json::value::parse( resp_body );
    resp_json["request_id"] = json::value( request_id );
    message.reply( status_codes::OK, resp_json );//把结果返回给客户端

    INFO_OUTPUT_CONSOLE( "Request ID: %s is replied!", request_id.c_str() );

    // when a thread is about to stop in situations that openssl it-self cannot recycle resources, we need call OPENSSL_thread_stop()
    OPENSSL_thread_stop();

    FUNC_END;
}

// Generate a unique ID for each HTTP request and this ID
// will be written into the log file to identify different requests
std::string listen_svr::CreateRequestID( const std::string & prefix )
{
    std::string ret;

    // Generate an 8 bytes rand number as the ID
    BN rand_bn = safeheron::rand::RandomBNStrict( 64 );
    rand_bn.ToHexStr( ret );

    return prefix + ret;
}

// Webhook通知 Callback function. Send a message to callback address using POST method
pplx::task<void> listen_svr::PostRequest( 
    const std::string & request_id, 
    const std::string & client_url, 
    const std::string & body )
{
    std::string path = "";
    http_client client{client_url};
    web::json::value resp_json = json::value::parse( body );
    resp_json["request_id"] = json::value( request_id );

    auto request = client.request( methods::POST, path, resp_json )
            .then( [request_id](http_response resp ) {
                if ( resp.status_code() != status_codes::OK ) {
                    ERROR( "Request ID: %s, call back failed! Status code: %d", request_id.c_str(), resp.status_code() );
                }
                else{
                    INFO( "Request ID: %s, call back successfully.", request_id.c_str() );
                }
            });
    return request;
}//发送post到客户端的webhook地址
