/**
 ******************************************************************************
  * File Name          : mbedtls.c
  * Description        : This file provides code for the configuration
  *                      of the mbedtls instances.
  ******************************************************************************
  * This notice applies to any and all portions of this file
  * that are not between comment pairs USER CODE BEGIN and
  * USER CODE END. Other portions of this file, whether 
  * inserted by the user or by software development tools
  * are owned by their respective copyright owners.
  *
  * Copyright (c) 2018 STMicroelectronics International N.V. 
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without 
  * modification, are permitted, provided that the following conditions are met:
  *
  * 1. Redistribution of source code must retain the above copyright notice, 
  *    this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  *    this list of conditions and the following disclaimer in the documentation
  *    and/or other materials provided with the distribution.
  * 3. Neither the name of STMicroelectronics nor the names of other 
  *    contributors to this software may be used to endorse or promote products 
  *    derived from this software without specific written permission.
  * 4. This software, including modifications and/or derivative works of this 
  *    software, must execute solely and exclusively on microcontroller or
  *    microprocessor devices manufactured by or for STMicroelectronics.
  * 5. Redistribution and use of this software other than as permitted under 
  *    this license is void and will automatically terminate your rights under 
  *    this license. 
  *
  * THIS SOFTWARE IS PROVIDED BY STMICROELECTRONICS AND CONTRIBUTORS "AS IS" 
  * AND ANY EXPRESS, IMPLIED OR STATUTORY WARRANTIES, INCLUDING, BUT NOT 
  * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
  * PARTICULAR PURPOSE AND NON-INFRINGEMENT OF THIRD PARTY INTELLECTUAL PROPERTY
  * RIGHTS ARE DISCLAIMED TO THE FULLEST EXTENT PERMITTED BY LAW. IN NO EVENT 
  * SHALL STMICROELECTRONICS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
  * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
  * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <errno.h>
#include "mbedtls.h"

/* USER CODE BEGIN 0 */
#include "lwip.h"
#include "term_io.h"
#include "net_sockets.h"
#include "errno.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/certs.h>
#include <mbedtls/error.h>
#include <lib.h>
#include <stdbool.h>
/* USER CODE END 0 */

/* USER CODE BEGIN 1 */

#define MAX_MESSAGE_SIZE 512
#define MAX_PATH_SIZE 255


typedef struct {
    // client input
    http_method method;
    char path[MAX_PATH_SIZE];
    char body[MAX_MESSAGE_SIZE];
} request;


typedef struct {
    char code[4];
    const char *body;
} response;

/* USER CODE END 1 */

/* Global variables ---------------------------------------------------------*/

/* USER CODE BEGIN 2 */
mbedtls_net_context listen_net_ctx;
mbedtls_net_context client_net_ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;


http_method parse_method(const char *str);

request *parse_request(const char buff[MAX_MESSAGE_SIZE]);

response handle_request(const request *req);

int read_socket(mbedtls_ssl_context *ssl, unsigned char buff[MAX_MESSAGE_SIZE]);

int write_socket(mbedtls_ssl_context *ssl, const unsigned char *message, size_t length);

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str) {
  ((void) level);

  xprintf("%s:%04d: %s\n", file, line, str);
}

inline unsigned min(const unsigned x, const unsigned y) {
  return x < y ? x : y;
}

inline unsigned long minl(const unsigned long x, const unsigned long y) {
  return x < y ? x : y;
}

/* USER CODE END 2 */

/* MBEDTLS init function */
void MX_MBEDTLS_Init(void) {
  /**
 */

  /* USER CODE BEGIN 3 */
  int ret = 0;
  const int DELAY = 6000;

  xprintf("Initializing mbedTLS structures...\n");
  mbedtls_net_init(&listen_net_ctx);
  mbedtls_net_init(&client_net_ctx);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_pk_init(&pkey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  // ugly wait for DHCP
  osDelay(DELAY);

  if ((ret = mbedtls_net_bind(&listen_net_ctx, NULL, "443", MBEDTLS_NET_PROTO_TCP)) != 0) {
    xprintf("Error! mbedtls_ssl_read returned -0x%x\n", -ret);
    return;
  }

  xprintf("Loading server certificate...\n");
  ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len);
  if (ret != 0) {
    xprintf("Error! mbedtls_x509_crt_parse returned -0x%x\n", -ret);
    return;
  }

  xprintf("Loading server private key...\n");
  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0);
  if (ret != 0) {
    xprintf("Error! mbedtls_pk_parse_key returned -0x%x\n", -ret);
    return;
  }

  xprintf("Loading CAs file...\n");
  ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);
  if (ret != 0) {
    xprintf("Error! mbedtls_x509_crt_parse returned -0x%x\n", -ret);
    return;
  }

  xprintf("Certificates loaded.\n\n");

  xprintf("Seeding the random number generator...\n");
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    xprintf("Error! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
    return;
  }
  xprintf("RNG seeded.\n\n");

  xprintf("Configuring SSL....\n");
  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    xprintf("Error! mbedtls_ssl_config_defaults returned -0x%x\n", -ret);
    return;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

  mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
    xprintf("Error! mbedtls_ssl_conf_own_cert returned -0x%x\n", -ret);
    return;
  }

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    xprintf("Error! mbedtls_ssl_setup returned -0x%x\n", -ret);
    return;
  }

  xprintf("HTTPS server initialized.\n\n");

  /* USER CODE END 3 */

}

/* USER CODE BEGIN 4 */

const char *method_to_str(http_method method) {
  switch (method) {
    case GET:
      return "GET";
    case HEAD:
      return "HEAD";
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    case CONNECT:
      return "CONNECT";
    case OPTIONS:
      return "OPTIONS";
    case TRACE:
      return "TRACE";
    case PATCH:
      return "PATCH";
    default:
      return "unknown";
  }
}

int single_connection(void) {
  int ret = 0;
  unsigned char *buff = malloc(MAX_MESSAGE_SIZE * sizeof(unsigned char));

  mbedtls_net_free(&client_net_ctx);
  mbedtls_ssl_session_reset(&ssl);

  xprintf("Waiting for a remote connection...\n");
  if ((ret = mbedtls_net_accept(&listen_net_ctx, &client_net_ctx,
                                NULL, 0, NULL)) != 0) {
    xprintf("Error! mbedtls_net_accept returned %d\n\n", ret);
    return ret;
  } else {
    xprintf("Connection incoming.\n\n");
  }

  // Set up input/output handle (BIO)
  mbedtls_ssl_set_bio(&ssl, &client_net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

  xprintf("Performing the SSL/TLS handshake...\n");
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      xprintf("Error! mbedtls_ssl_handshake returned %d\n\n", ret);
      return ret;
    }
  }
  xprintf("Handshake finished.\n\n");

  xprintf("Reading client's message...\n");
  if ((ret = read_socket(&ssl, buff)) < 0) {
    return ret;
  } else {
    xprintf("Read %d bytes.\n\n", ret);
  }

  xprintf("Parsing input as an HTTP message...\n");
  request *received_req = parse_request((char *) buff);

  xprintf("Request method: %s\n", method_to_str(received_req->method));
  xprintf("Request path: %s\n\n", received_req->path);


  xprintf("Processing HTTP request...\n");
  response resp = handle_request(received_req);

  xprintf("Writing response...\n");
  memset(buff, 0, MAX_MESSAGE_SIZE * sizeof(unsigned char));
  ret = snprintf((char *) buff, MAX_MESSAGE_SIZE,
                 "HTTP/1.0 %s\r\nContent-Type: text/html\r\n\r\n%s\r\n",
                 resp.code, resp.body);
  if (ret < 0)
    return ret;

  if ((ret = write_socket(&ssl, buff, (size_t) ret)) < 0) {
    return ret;
  } else {
    xprintf("Written %d bytes.\n\n", ret);
  }

  xprintf("Closing the connection...\n");

  while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      xprintf("Error! mbedtls_ssl_close_notify returned %d\n\n", ret);
      return ret;
    }
  }
  xprintf("Connection closed.\n\n");


  free(received_req);
  return 0;
}

int read_socket(mbedtls_ssl_context *ssl, unsigned char buff[MAX_MESSAGE_SIZE]) {
  int ret = 0;
  unsigned to_read = MAX_MESSAGE_SIZE - 1;

  do {
    memset(buff, 0, MAX_MESSAGE_SIZE);
    ret = mbedtls_ssl_read(ssl, buff, to_read);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret <= 0) {
    switch (ret) {
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        xprintf("Connection was closed gracefully\n");
        break;
      case MBEDTLS_ERR_NET_CONN_RESET:
        xprintf("Connection was reset by peer\n");
        break;
      default:
        xprintf("mbedtls_ssl_read returned -0x%x\n", -ret);
    }
  }

  return ret;
}


int write_socket(mbedtls_ssl_context *ssl, const unsigned char *message, size_t length) {
  int ret = 0;

  while ((ret = mbedtls_ssl_write(ssl, message, length)) <= 0) {
    if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
      xprintf("Error! mbedtls_ssl_write returned %d\n\n", ret);
      return ret;
    }

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      xprintf("Error! mbedtls_ssl_write returned %d\n\n", ret);
      return ret;
    }
  }

  return ret;
}


// handles the request b
response handle_request(const request *req) {
  response resp = {0};

  if (req->method == GET) {
    strcpy(resp.code, "200");
    resp.body = "I'm sending you a response to GET request";
  } else {
    strcpy(resp.code, "405");
    resp.body = "No action bound to this HTTP method, sorry!";
  }

  return resp;
}

/**
 * Parses HTTP message. The first line consists of the HTTP Method,
 * resource path and HTTP version.
 * In further lines HTTP headers are specified, which are skipped by this function.
 * After an empty line there is optional message body.
 *
 * @param buff Array containing data sent by the connecting client
 * @return request Struct describing the request
 */
request *parse_request(const char input[MAX_MESSAGE_SIZE]) {
  request *req = calloc(1, sizeof(request));

  // space for passing around null-terminated strings
  // being part of the request
  const size_t TMP_SIZE = 10;
  char tmp[TMP_SIZE + 1];
  memset(tmp, 0, TMP_SIZE + 1);

  const char *it = input;

  // parse method
  const char *next = strchr(it, ' ');
  memcpy(tmp, it, minl(next - it, TMP_SIZE));
  req->method = parse_method(tmp);

  // parse path
  it = next + 1;
  next = strchr(it, ' ');
  const size_t path_len = next - it;

  memcpy(&req->path, it, minl(next - it, MAX_PATH_SIZE - 1));
  req->path[path_len] = '\0';

  // parse body

  it = next + 1;
  next = strstr(it, "\r\n\r\n");
  it = next + 4;
  const size_t body_len = strnlen(it, MAX_MESSAGE_SIZE - 1);
  memcpy(&req->body, it, body_len);
  req->body[body_len] = '\0';

  return req;
}


/**
 * Matches HTTP method string to one of enum values.
 * @param str
 * @return
 */
http_method parse_method(const char *str) {
  if (strcmp("GET", str) == 0) {
    return GET;
  } else if (strcmp("HEAD", str) == 0) {
    return HEAD;
  } else if (strcmp("POST", str) == 0) {
    return POST;
  } else if (strcmp("PUT", str) == 0) {
    return PUT;
  } else if (strcmp("DELETE", str) == 0) {
    return DELETE;
  } else if (strcmp("CONNECT", str) == 0) {
    return CONNECT;
  } else if (strcmp("OPTIONS", str) == 0) {
    return OPTIONS;
  } else if (strcmp("TRACE", str) == 0) {
    return TRACE;
  } else if (strcmp("PATCH", str) == 0) {
    return PATCH;
  } else {
    return UNKNOWN;
  }
}

/* USER CODE END 4 */

/**
  * @}
  */

/**
  * @}
  */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
