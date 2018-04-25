// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/tlsio_options.h"
#include "azure_c_shared_utility/xio_endpoint.h"
#include "xio_endpoint_config_tls.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

typedef struct MBED_ENDPOINT_INSTANCE_TAG
{
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
} MBED_ENDPOINT_INSTANCE;

static void debug_callback(void *ctx, int level,
    const char *file, int line, const char *str)
{
    // TODO: case the level
    ((void)level);
    (void)ctx;
    LogInfo("%s:%04d: %s", file, line, str);
}

/* Codes_SRS_XIO_ENDPOINT_30_000: [ The xio_endpoint_create shall allocate and initialize all necessary resources and return an instance of the xio_endpoint. ]*/
XIO_ENDPOINT_INSTANCE_HANDLE mbed_tls_create()
{
    MBED_ENDPOINT_INSTANCE* result = malloc(sizeof(MBED_ENDPOINT_INSTANCE));
    if (result != NULL)
    {
        memset(result, 0, sizeof(MBED_ENDPOINT_INSTANCE));
    }
    else
    {
        /* Codes_SRS_XIO_ENDPOINT_30_001: [ If any resource allocation fails, xio_endpoint_create shall log an error and return NULL. ]*/
        LogError("Failed to create endpoint");
    }
    return (XIO_ENDPOINT_INSTANCE_HANDLE)result;
}

/* Codes_SRS_XIO_ENDPOINT_30_010: [ The xio_endpoint parameter is guaranteed to be non-NULL by the calling xio_impl, so concrete implementations shall not add redundant checking. ]*/
void mbed_tls_destroy(XIO_ENDPOINT_INSTANCE_HANDLE xio_endpoint_instance)
{
    MBED_ENDPOINT_INSTANCE* context = (MBED_ENDPOINT_INSTANCE*)xio_endpoint_instance;
    /* Codes_SRS_XIO_ENDPOINT_30_011: [ The xio_endpoint_destroy shell release all of the xio_endpoint resources. ]*/
    free(context);
}

/* Codes_SRS_XIO_ENDPOINT_30_020: [ The xio_endpoint parameter is guaranteed to be non-NULL by the calling xio_impl, so concrete implementations shall not add redundant checking. ]*/
static XIO_ASYNC_RESULT mbed_tls_open(XIO_ENDPOINT_INSTANCE_HANDLE xio_endpoint_instance, XIO_ENDPOINT_CONFIG_HANDLE xio_endpoint_config)
{
    XIO_ASYNC_RESULT result;
    int ret;
    MBED_ENDPOINT_INSTANCE* context = (MBED_ENDPOINT_INSTANCE*)xio_endpoint_instance;
    TLS_CONFIG_DATA* config = (TLS_CONFIG_DATA*)xio_endpoint_config;
 
    mbedtls_net_init(&context->server_fd);
    mbedtls_ssl_init(&context->ssl);
    mbedtls_ssl_config_init(&context->conf);
    mbedtls_x509_crt_init(&context->cacert);
    mbedtls_ctr_drbg_init(&context->ctr_drbg);
    mbedtls_x509_crt_init(&context->cacert);

    mbedtls_entropy_init(&context->entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&context->ctr_drbg, mbedtls_entropy_func, &context->entropy,
        (const unsigned char *)pers,
        strlen(pers))) != 0)
    {
        LogError("mbedtls_ctr_drbg_seed returned %d", ret);
        result = XIO_ASYNC_RESULT_FAILURE;
    }
    else if ((ret = mbedtls_net_connect(&context->server_fd, config->hostname,
        config->port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        LogError("mbedtls_net_connect returned %d", ret);
        result = XIO_ASYNC_RESULT_FAILURE;
    }
    else if ((ret = mbedtls_ssl_config_defaults(&context->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        LogError("mbedtls_ssl_config_defaults returned %d", ret);
        result = XIO_ASYNC_RESULT_FAILURE;
    }
    else if (config->options.trusted_certs == NULL)
    {
        LogError("trusted cert option has not been set");
        result = XIO_ASYNC_RESULT_FAILURE;
    }
}
    else if ((ret = mbedtls_x509_crt_parse(&context->cacert, config->options.trusted_certs, strlen(config->options.trusted_certs))) != 0)
    {
        LogError("mbedtls_x509_crt_parse returned %d", ret);
        result = XIO_ASYNC_RESULT_FAILURE;
    }
    else
    {
        mbedtls_ssl_conf_ca_chain(&context->conf, &context->cacert, NULL);

        // Set the random engine to use
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        // Supply a debug callback
        mbedtls_ssl_conf_dbg(&conf, debug_callback, stdoutxxx);

        // Set up the SSL context to use the configuration we've established
        if ((ret = mbedtls_ssl_set_hostname(&context->ssl, config->hostname)) != 0)
        {
            LogError("mbedtls_ssl_set_hostname returned %d", ret);
            result = XIO_ASYNC_RESULT_FAILURE;
        }
        else
        {
            // Tell the SSL context which functions to use for network i/o
            mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
            result = XIO_ASYNC_RESULT_SUCCESS;
        }
    }

    return result;
}


/* Codes_SRS_XIO_ENDPOINT_30_040: [ All parameters are guaranteed to be non-NULL by the calling xio_impl, so concrete implementations shall not add redundant checking. ]*/
/* Codes_SRS_XIO_ENDPOINT_30_041: [ The xio_endpoint_read shall attempt to read buffer_size characters into buffer. ]*/
static int mbed_tls_read(XIO_ENDPOINT_INSTANCE_HANDLE xio_endpoint_instance, uint8_t* buffer, uint32_t buffer_size)
{
    int rcv_bytes;
    MBED_ENDPOINT_INSTANCE* context = (MBED_ENDPOINT_INSTANCE*)xio_endpoint_instance;
    // The buffer_size is guaranteed by the calling framweork to be less than INT_MAX
    // in order to ensure that this cast is safe
    if ((rcv_bytes = mbedtls_ssl_read(&context->ssl, buffer, buffer_size)) > 0)
    {
        /* Codes_SRS_XIO_ENDPOINT_30_042: [ On success, xio_endpoint_read shall return the number of characters copied into buffer. ]*/
    }
    else if (rcv_bytes == MBEDTLS_ERR_SSL_WANT_READ || rcv_bytes == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        /* Codes_SRS_XIO_ENDPOINT_30_044: [ If no data is available xio_endpoint_read shall return 0. ]*/
        rcv_bytes = 0;
    }
    else
    {
        /* Codes_SRS_XIO_ENDPOINT_30_043: [ On failure, xio_endpoint_read shall log an error and return XIO_ASYNC_RW_RESULT_FAILURE. ]*/
        LogError("mbedtls_ssl_read failure");
        rcv_bytes = XIO_ASYNC_RESULT_FAILURE;
    }
    return rcv_bytes;
}

/* Codes_SRS_XIO_ENDPOINT_30_050: [ All parameters are guaranteed to be non-NULL by the calling xio_impl, so concrete implementations shall not add redundant checking. ]*/
/* Codes_SRS_XIO_ENDPOINT_30_051: [ The xio_endpoint_write shall attempt to write buffer_size characters from buffer to its underlying data sink. ]*/
static int mbed_tls_write(XIO_ENDPOINT_INSTANCE_HANDLE xio_endpoint_instance, const uint8_t* buffer, uint32_t count)
{
    int result;
    MBED_ENDPOINT_INSTANCE* context = (MBED_ENDPOINT_INSTANCE*)xio_endpoint_instance;
    // Check to see if the socket will not block
    // The count is guaranteed by the calling framweork to be less than INT_MAX
    // in order to ensure that this cast is safe
    if ((result = mbedtls_ssl_write(&ssl, buffer, count)) > 0)
    {
        /* Codes_SRS_XIO_ENDPOINT_30_052: [ On success, xio_endpoint_write shall return the number of characters from buffer that are sent. ]*/
    }
    else if (rcv_bytes == MBEDTLS_ERR_SSL_WANT_READ || rcv_bytes == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        /* Codes_SRS_XIO_ENDPOINT_30_054: [ If the underlying data sink is temporarily unable to accept data, xio_endpoint_write shall return 0. ]*/
        result = 0;
    }
    else
    {
        /* Codes_SRS_XIO_ENDPOINT_30_053: [ On failure, xio_endpoint_write shall log an error and return XIO_ASYNC_RW_RESULT_FAILURE. ]*/
        LogInfo("Hard error from CFWriteStreamWrite: %d", CFErrorGetCode(write_error));
        result = XIO_ASYNC_RESULT_FAILURE;
    }

    return result;
}

/* Codes_SRS_XIO_ENDPOINT_30_030: [ All parameters are guaranteed to be non-NULL by the calling xio_impl, so concrete implementations shall not add redundant checking. ]*/
/* Codes_SRS_XIO_ENDPOINT_30_031: [ The xio_endpoint_close shall do what is necessary to close down its operation. ]*/
int mbed_tls_close(XIO_ENDPOINT_INSTANCE_HANDLE xio_endpoint_instance)
{
    MBED_ENDPOINT_INSTANCE* context = (MBED_ENDPOINT_INSTANCE*)xio_endpoint_instance;
    mbedtls_net_free(&context->server_fd);
    mbedtls_ssl_free(&context->ssl);
    mbedtls_ssl_config_free(&context->conf);
    mbedtls_ctr_drbg_free(&context->ctr_drbg);
    mbedtls_entropy_free(&context->entropy);
    mbedtls_x509_crt_free(&context->cacert);
    /* Codes_SRS_XIO_ENDPOINT_30_032: [ On completion, xio_endpoint_close shall return XIO_ASYNC_RESULT_SUCCESS. ] */
    return XIO_ASYNC_RESULT_SUCCESS;
}

static const XIO_ENDPOINT_INTERFACE mbed_tls =
{
    mbed_tls_create,
    mbed_tls_destroy,
    mbed_tls_open,
    mbed_tls_close,
    mbed_tls_read,
    mbed_tls_write
};

const XIO_ENDPOINT_INTERFACE* xio_endpoint_tls_mbed_get_interface()
{
    return &mbed_tls;
}

const IO_INTERFACE_DESCRIPTION* socketio_get_interface_description(void)
{
    return NULL;
}

