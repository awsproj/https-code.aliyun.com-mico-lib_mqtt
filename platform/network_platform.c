/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifdef __cplusplus
extern "C"
{
#endif

#include <timer_platform.h>
#include <network_interface.h>

#include "mqtt_error.h"
#include "mqtt_log.h"
#include "mqtt_config.h"
#include "root_ca_cert.h"
#include "network_platform.h"
#include "common.h"
#include "debug.h"

//#define aws_platform_log(M, ...) custom_log("", M, ##__VA_ARGS__)
#define aws_platform_log(M, ...)

extern void ssl_set_client_cert( const char *_cert_pem, const char *private_key_pem );

/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10

/*
 * This is a function to do further verification if needed on the cert received
 */

static void _iot_tls_set_connect_params( Network *pNetwork, char *pRootCALocation,
                                         char *pDeviceCertLocation,
                                         char *pDevicePrivateKeyLocation,
                                         char *pDestinationURL,
                                         uint16_t destinationPort,
                                         uint32_t timeout_ms,
                                         bool ServerVerificationFlag,
                                         bool isUseSSLFlag )
{
    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
    pNetwork->tlsConnectParams.isUseSSL = isUseSSLFlag;
}

static OSStatus socket_gethostbyname( const char * domain, uint8_t * addr, uint8_t addrLen )
{
    struct hostent* host = NULL;
    struct in_addr in_addr;
    char **pptr = NULL;
    char *ip_addr = NULL;

    if ( addr == NULL || addrLen < 16 )
    {
        return kGeneralErr;
    }

    host = gethostbyname( domain );
    if ( (host == NULL) || (host->h_addr_list) == NULL )
    {
        return kGeneralErr;
    }

    pptr = host->h_addr_list;
    in_addr.s_addr = *(uint32_t *) (*pptr);
    ip_addr = inet_ntoa( in_addr );
    memset( addr, 0, addrLen );
    memcpy( addr, ip_addr, strlen( ip_addr ) );

    return kNoErr;
}

static OSStatus socket_tcp_connect( int *fd, char *ipstr, uint16_t port )
{
    OSStatus err = kNoErr;
    int opt = 0;
    struct sockaddr_in addr;

    *fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    require_action( IsValidSocket( *fd ), exit,
                    aws_platform_log("ERROR: Unable to create the tcp_client.") );

    opt = 1;
    setsockopt( *fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &opt, sizeof(opt) );
    opt = 10;
    setsockopt( *fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *) &opt, sizeof(opt) );
    opt = 5;
    setsockopt( *fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &opt, sizeof(opt) );
    opt = 3;
    setsockopt( *fd, IPPROTO_TCP, TCP_KEEPCNT, (void *) &opt, sizeof(opt) );

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr( ipstr );
    addr.sin_port = htons( port );

    err = connect( *fd, (struct sockaddr *) &addr, sizeof(addr) );
    if ( err != kNoErr )
    {
        close( *fd );
        *fd = -1;
        goto exit;
    }

    return kNoErr;
    exit:
    return kGeneralErr;
}

static int socket_send( Network *pNetwork, void *data, size_t len )
{
    int ret = 0;
    if ( pNetwork->tlsConnectParams.isUseSSL == true )
    {
#ifdef MQTT_USE_SSL
        ret = ssl_send( pNetwork->tlsDataParams.ssl, data, len );
#endif
    } else
    {
        ret = send( pNetwork->tlsDataParams.server_fd, data, len, 0 );
    }

    return ret;
}

IoT_Error_t iot_tls_init( Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                          char *pDevicePrivateKeyLocation,
                          char *pDestinationURL,
                          uint16_t destinationPort,
                          uint32_t timeout_ms, bool ServerVerificationFlag, bool isUseSSLFlag )
{
    _iot_tls_set_connect_params( pNetwork, pRootCALocation, pDeviceCertLocation,
                                 pDevicePrivateKeyLocation,
                                 pDestinationURL,
                                 destinationPort,
                                 timeout_ms, ServerVerificationFlag, isUseSSLFlag );

    pNetwork->connect = iot_tls_connect;
    pNetwork->read = iot_tls_read;
    pNetwork->write = iot_tls_write;
    pNetwork->disconnect = iot_tls_disconnect;
    pNetwork->isConnected = iot_tls_is_connected;
    pNetwork->destroy = iot_tls_destroy;

    pNetwork->tlsDataParams.server_fd = -1;
    pNetwork->tlsDataParams.ssl = NULL;
#ifdef MQTT_USE_SSL
    ssl_set_client_version( TLS_V1_2_MODE );
#endif

    return SUCCESS;
}

IoT_Error_t iot_tls_is_connected( Network *pNetwork )
{
    /* Use this to add implementation which can check for physical layer disconnect */
    return NETWORK_PHYSICAL_LAYER_CONNECTED;
}

IoT_Error_t iot_tls_connect( Network *pNetwork, TLSConnectParams *params )
{
    OSStatus err = kNoErr;

    char ipstr[16];
    int socket_fd = -1;

    if ( NULL == pNetwork )
    {
        return NULL_VALUE_ERROR;
    }

    if ( NULL != params )
    {
        _iot_tls_set_connect_params( pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
                                     params->pDevicePrivateKeyLocation,
                                     params->pDestinationURL,
                                     params->DestinationPort,
                                     params->timeout_ms,
                                     params->ServerVerificationFlag,
                                     params->isUseSSL );
    }

    err = socket_gethostbyname( pNetwork->tlsConnectParams.pDestinationURL, (uint8_t *) ipstr, 16 );
    if ( err != kNoErr )
    {
        aws_platform_log("ERROR: Unable to resolute the host address.");
        return TCP_CONNECTION_ERROR;
    }
    aws_platform_log("host:%s, ip:%s", pNetwork->tlsConnectParams.pDestinationURL, ipstr);

    err = socket_tcp_connect( &socket_fd, ipstr, pNetwork->tlsConnectParams.DestinationPort );
    if ( err != kNoErr )
    {
        aws_platform_log("ERROR: Unable to resolute the tcp connect");
        return TCP_CONNECTION_ERROR;
    }
    aws_platform_log("tcp connected fd: %d", socket_fd);

#ifdef MQTT_USE_SSL
    int errno;
    int root_ca_len = 0;
    if ( pNetwork->tlsConnectParams.isUseSSL == false )
    {
        pNetwork->tlsDataParams.server_fd = socket_fd;
        return SUCCESS;
    }

    if ( (pNetwork->tlsConnectParams.pDeviceCertLocation != NULL)
         && (pNetwork->tlsConnectParams.pDevicePrivateKeyLocation != NULL) )
    {
        pNetwork->tlsDataParams.clicert = client_cert;
        pNetwork->tlsDataParams.pkey = private_key;
        ssl_set_client_cert( pNetwork->tlsDataParams.clicert, pNetwork->tlsDataParams.pkey );
        aws_platform_log("use client ca");
    }

    if ( (pNetwork->tlsConnectParams.ServerVerificationFlag == true) )
    {
        pNetwork->tlsDataParams.cacert = root_ca;
        root_ca_len = strlen( pNetwork->tlsDataParams.cacert );
        aws_platform_log("use server ca");
    } else
    {
        pNetwork->tlsDataParams.cacert = NULL;
        root_ca_len = 0;
    }
    pNetwork->tlsDataParams.ssl = ssl_connect( socket_fd,
                                               root_ca_len,
                                               pNetwork->tlsDataParams.cacert, &errno );
    aws_platform_log("fd: %d, err:  %d", socket_fd ,errno);
    if ( pNetwork->tlsDataParams.ssl == NULL )
    {
        aws_platform_log("ssl connect err");
        close( socket_fd );
        pNetwork->tlsDataParams.server_fd = -1;
        return SSL_CONNECTION_ERROR;
    }

    aws_platform_log("ssl connected");
#endif
    pNetwork->tlsDataParams.server_fd = socket_fd;
    return SUCCESS;
}

IoT_Error_t iot_tls_write( Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer,
size_t *written_len )
{
    size_t written_so_far;
    bool isErrorFlag = false;
    int frags, ret = 0;

    aws_platform_log("socket write: %d", len);

    for ( written_so_far = 0, frags = 0;
        written_so_far < len && !has_timer_expired( timer ); written_so_far += ret, frags++ )
    {
        while ( (!has_timer_expired( timer ))
                &&
                ((ret = socket_send( pNetwork, pMsg + written_so_far,
                                     len - written_so_far ))
                 <= 0) )
        {
            if ( ret < 0 )
            {
                aws_platform_log(" failed");
                /* All other negative return values indicate connection needs to be reset.
                 * Will be caught in ping request so ignored here */
                isErrorFlag = true;
                break;
            }
        }
        if ( isErrorFlag )
        {
            break;
        }
    }

    *written_len = written_so_far;
    aws_platform_log("socket write done: %d", written_so_far);
    if ( isErrorFlag )
    {
        return NETWORK_SSL_WRITE_ERROR;
    } else if ( has_timer_expired( timer ) && written_so_far != len )
    {
        return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
    }

    return SUCCESS;
}

IoT_Error_t iot_tls_read( Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer,
size_t *read_len )
{
    size_t rxLen = 0;
    int ret = 0;
    int fd = pNetwork->tlsDataParams.server_fd;
    fd_set readfds;
    struct timeval t;
    int time_out = left_ms( timer );

    FD_ZERO( &readfds );
    FD_SET( fd, &readfds );

    t.tv_sec = time_out / 1000;
    t.tv_usec = (time_out % 1000) * 1000;

    aws_platform_log("socket fd:%d, read: %d, left_ms: %ld", pNetwork->tlsDataParams.server_fd, len, left_ms(timer));
    while ( len > 0 )
    {
        if ( pNetwork->tlsConnectParams.isUseSSL == true )
        {
#ifdef MQTT_USE_SSL
            if ( ssl_pending( pNetwork->tlsDataParams.ssl ) )
            {
                ret = ssl_recv( pNetwork->tlsDataParams.ssl, pMsg, len );
            } else
            {
                ret = select( fd + 1, &readfds, NULL, NULL, &t );
                aws_platform_log("select ret %d", ret);
                if ( ret <= 0 )
                {
                    break;
                }

                if ( !FD_ISSET( fd, &readfds ) )
                {
                    aws_platform_log("fd is set err");
                    break;
                }
                ret = ssl_recv( pNetwork->tlsDataParams.ssl, pMsg, len );
            }
#endif
        } else
        {
            ret = select( fd + 1, &readfds, NULL, NULL, &t );
            aws_platform_log("select ret %d", ret);
            if ( ret <= 0 )
            {
                break;
            }

            if ( !FD_ISSET( fd, &readfds ) )
            {
                aws_platform_log("fd is set err");
                break;
            }
            ret = recv( pNetwork->tlsDataParams.server_fd, pMsg, len, 0 );
        }

        if ( ret >= 0 )
        {
            rxLen += ret;
            pMsg += ret;
            len -= ret;
        } else if ( ret < 0 )
        {
            aws_platform_log("socket read err");
            return NETWORK_SSL_READ_ERROR;
        }

        // Evaluate timeout after the read to make sure read is done at least once
        if ( has_timer_expired( timer ) )
        {
            aws_platform_log("read time out");
            break;
        }
    }

    aws_platform_log("socket read done: %d", rxLen);

    if ( len == 0 )
    {
        *read_len = rxLen;
        return SUCCESS;
    }

    if ( rxLen == 0 )
    {
        return NETWORK_SSL_NOTHING_TO_READ;
    } else
    {
        return NETWORK_SSL_READ_TIMEOUT_ERROR;
    }
}

IoT_Error_t iot_tls_disconnect( Network *pNetwork )
{
    /* All other negative return values indicate connection needs to be reset.
     * No further action required since this is disconnect call */
    if ( pNetwork->tlsDataParams.ssl != NULL )
    {
        ssl_close( pNetwork->tlsDataParams.ssl );
        pNetwork->tlsDataParams.ssl = NULL;
    }

    if ( pNetwork->tlsDataParams.server_fd != -1 )
    {
        close( pNetwork->tlsDataParams.server_fd );
        pNetwork->tlsDataParams.server_fd = -1;
    }

    return SUCCESS;
}

IoT_Error_t iot_tls_destroy( Network *pNetwork )
{
    return SUCCESS;
}

char *mqtt_client_id_get( char clientid[30] )
{
    uint8_t mac[6];
    char mac_str[13];

    mico_wlan_get_mac_address( mac );
    sprintf( mac_str, "%02X%02X%02X%02X%02X%02X",
             mac[0],
             mac[1], mac[2], mac[3], mac[4], mac[5] );
    sprintf( clientid, "%s_%s", MQTT_CLIENT_ID, mac_str );

    return clientid;
}

#ifdef __cplusplus
}
#endif
