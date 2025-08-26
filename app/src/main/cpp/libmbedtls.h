//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/mbedtls/entropy.h"
#include <inttypes.h>

#ifndef MBEDTLS_ANDROID_LIBMBEDTLS_H
#define MBEDTLS_ANDROID_LIBMBEDTLS_H
#define MBEDTLS_CLIENT_READ_SIZE        (16*1024)
#define SS_MBEDTLS_ERR_ENTROPY 551
#define SS_MBEDTLS_ERR_SSL_CONFIG 552
#define SS_MBEDTLS_ERR_SSL_SETUP 553
#define SS_MBEDTLS_ERR_HANDSHAKE_STEP 554
#define SS_MBEDTLS_ERR_PARSE_CERT 555
#define SS_MBEDTLS_ERR_PARSE_KEY 556
#define SS_MBEDTLS_ERR_CONFIG_CLIENT_CERT 557

typedef void *mbedtls_client_handle_t;

mbedtls_ssl_context ssl_context;
mbedtls_ssl_config ssl_config;
mbedtls_ctr_drbg_context random_byte_generator;
mbedtls_entropy_context entropy_context;
mbedtls_x509_crt cert_chain1;
mbedtls_x509_crt cert_chain2;
mbedtls_x509_crt cert_chain3;
mbedtls_pk_context key_pair;

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_init(JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_setupSSLContextNative(JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_setIOFuncs(JNIEnv *, jobject, jstring);

JNIEXPORT void JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_configurePsk(JNIEnv *, jobject, jcharArray, jint, jbyteArray, jint);

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_executeNextHandshakeStep(JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getCurrentHandshakeState(JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_configureCipherSuites(JNIEnv *, jobject, jintArray);

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_setMinimumProtocolVersion(JNIEnv *, jobject, jint);

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_setMaximumProtocolVersion(JNIEnv *, jobject, jint);

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_enableDebug(JNIEnv *, jobject, jint);

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_configureClientCertNative(JNIEnv *, jobject, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_configureRootCACertNative(JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_simplisafe_mbedtls_MbedTLS_getIssuerNameNative(JNIEnv *, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_MbedTLS_write(JNIEnv *, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_MbedTLS_read(JNIEnv *, jobject, jint, jbyteArray);

#endif //MBEDTLS_ANDROID_LIBMBEDTLS_H

JNIEXPORT jlong JNICALL Java_com_simplisafe_mbedtls_MbedTLS_initClientImpl(
        JNIEnv *env,
        jobject thisObj,
        jint transport,
        jintArray cipher_suites,
        jint num_cipher_suites,
        jbyteArray psk,
        jint psk_len,
        jbyteArray psk_id,
        jint psk_id_len
);

JNIEXPORT void Java_com_simplisafe_mbedtls_MbedTLS_deallocateClient(JNIEnv *env, jobject thisObj, jlong handle);

JNIEXPORT jint Java_com_simplisafe_mbedtls_MbedTLS_initClientHandshake(JNIEnv *env, jobject thisObj, jlong handle);

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_clientWriteNative(JNIEnv *env, jobject thisObj, jlong handle, jbyteArray data,
                                                      jint length);

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_clientReadNative(JNIEnv *env, jobject thisObj, jlong handle, jbyteArray data,
                                                     jint length);
