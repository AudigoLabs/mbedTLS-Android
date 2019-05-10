//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include <jni.h>
#include "libmbedtls.h"

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setupSSLContext(JNIEnv *env, jobject thisObj) {
    mbedtls_ssl_init(&ssl_context);
    mbedtls_ssl_config_init(&ssl_config);
    int ret = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    printf("HEYSUP config ret %d", ret);
    return ret;
}