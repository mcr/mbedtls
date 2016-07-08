/*
 *  Reads a certificate, extracts the embedded EUI-64 (-48) and configures
 *  the ethernet and 802.15.4 devices with that address.
 *
 *  Copyright (C) 2016, Michael Richardson <mcr@sandelman.ca>
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODE_NONE               0
#define MODE_FILE               1
#define MODE_SSL                2

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "/boot/device.crt"
#define DFL_CA_FILE             "/boot/vendor.crt"
#define DFL_CRL_FILE            ""
#define DFL_CA_PATH             ""
#define DFL_DEBUG_LEVEL         0
#define DFL_PERMISSIVE          0

#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (none)\n" \
    "    crl_file=%%s         The single CRL file you want to use\n" \
    "                        default: \"\" (none)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (none) (overrides ca_file)\n"

#define USAGE \
    "\n usage: cert_app param=<>...\n"                  \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: cert.crt\n"      \
    USAGE_IO                                            \
    "    server_port=%%d      default: 4433\n"          \
    "    debug_level=%%d      default: 0 (disabled)\n"  \
    "    permissive=%%d       default: 0 (disabled)\n"  \
    "\n"

/*
 * global options
 */
struct options
{
    int mode;                   /* the mode to run the application in   */
    const char *filename;       /* filename of the certificate file     */
    const char *ca_file;        /* the file with the CA certificate(s)  */
    const char *crl_file;       /* the file with the CRL to use         */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    int debug_level;            /* level of debugging                   */
    int permissive;             /* permissive parsing                   */
} opt;

#if 0
static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}
#endif

static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

    mbedtls_printf( "\nVerify requested for (Depth %d):\n", depth );
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    mbedtls_printf( "%s", buf );

    if ( ( *flags ) == 0 )
        mbedtls_printf( "  This certificate has no flags\n" );
    else
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        mbedtls_printf( "%s\n", buf );
    }

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret = 0;
    mbedtls_net_context server_fd;
    unsigned char buf[1024];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_x509_crl cacrl;
    mbedtls_pk_context pkey;
    int i;
    uint32_t flags;
    int verify = 0;
    char *p, *q;

    /*
     * Set to sane values
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );
    /* Zeroize structure as CRL parsing is not supported and we have to pass
       it to the verify function */
    memset( &cacrl, 0, sizeof(mbedtls_x509_crl) );
    mbedtls_pk_init( &pkey );

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
        ret = 2;
        goto exit;
    }

    opt.mode                = DFL_MODE;
    opt.filename            = DFL_FILENAME;
    opt.ca_file             = DFL_CA_FILE;
    opt.crl_file            = DFL_CRL_FILE;
    opt.ca_path             = DFL_CA_PATH;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.permissive          = DFL_PERMISSIVE;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "--filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "--ca_file" ) == 0 )
            opt.ca_file = q;
        else if( strcmp( p, "--crl_file" ) == 0 )
            opt.crl_file = q;
        else if( strcmp( p, "--ca_path" ) == 0 )
            opt.ca_path = q;
        else if( strcmp( p, "--debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else if( strcmp( p, "--permissive" ) == 0 )
        {
            opt.permissive = atoi( q );
            if( opt.permissive < 0 || opt.permissive > 1 )
                goto usage;
        }
        else
            goto usage;
    }

    /*
     * 1.1. Load the trusted CA
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    if( strlen( opt.ca_path ) )
    {
        ret = mbedtls_x509_crt_parse_path( &cacert, opt.ca_path );
        verify = 1;
    }
    else if( strlen( opt.ca_file ) )
    {
        ret = mbedtls_x509_crt_parse_file( &cacert, opt.ca_file );
        verify = 1;
    }

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );


    if( strlen( opt.crl_file ) )
    {
        if( ( ret = mbedtls_x509_crl_parse_file( &cacrl, opt.crl_file ) ) != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crl_parse returned -0x%x\n\n", -ret );
            goto exit;
        }

        verify = 1;
    }

    {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt *cur = &crt;
        mbedtls_x509_crt_init( &crt );

        /*
         * 1.1. Load the certificate(s)
         */
        mbedtls_printf( "\n  . Loading the certificate(s) ..." );
        fflush( stdout );

        ret = mbedtls_x509_crt_parse_file( &crt, opt.filename );

        if( ret < 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret );
            mbedtls_x509_crt_free( &crt );
            goto exit;
        }

        if( opt.permissive == 0 && ret > 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse failed to parse %d certificates\n\n", ret );
            mbedtls_x509_crt_free( &crt );
            goto exit;
        }

        mbedtls_printf( " ok\n" );

        /*
         * 1.2 Print the certificate(s)
         */
        while( cur != NULL )
        {
            mbedtls_printf( "  . Peer certificate information    ...\n" );
            ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                                 cur );
            if( ret == -1 )
            {
                mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret );
                mbedtls_x509_crt_free( &crt );
                goto exit;
            }

            mbedtls_printf( "%s\n", buf );

            cur = cur->next;
        }

        ret = 0;

        /*
         * 1.3 Verify the certificate
         */
        if( verify )
        {
            mbedtls_printf( "  . Verifying X.509 certificate..." );

            if( ( ret = mbedtls_x509_crt_verify( &crt, &cacert, &cacrl, NULL, &flags,
                                         my_verify, NULL ) ) != 0 )
            {
                char vrfy_buf[512];

                mbedtls_printf( " failed\n" );

                mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

                mbedtls_printf( "%s\n", vrfy_buf );
            }
            else
                mbedtls_printf( " ok\n" );
        }

        mbedtls_x509_crt_free( &crt );
    }

exit:

    mbedtls_net_free( &server_fd );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_x509_crt_free( &clicert );
    mbedtls_pk_free( &pkey );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    if( ret < 0 )
        ret = 1;

    return( ret );
}
