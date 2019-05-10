//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include "mbedtls/ssl.h"

#ifndef MBEDTLS_ANDROID_LIBMBEDTLS_H
#define MBEDTLS_ANDROID_LIBMBEDTLS_H

mbedtls_ssl_context ssl_context;
mbedtls_ssl_config ssl_config;

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setupSSLContext(JNIEnv *, jobject);

#endif //MBEDTLS_ANDROID_LIBMBEDTLS_H
