//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/mbedtls/entropy.h"

#ifndef MBEDTLS_ANDROID_LIBMBEDTLS_H
#define MBEDTLS_ANDROID_LIBMBEDTLS_H

mbedtls_ssl_context ssl_context;
mbedtls_ssl_config ssl_config;
mbedtls_ctr_drbg_context random_byte_generator;
mbedtls_entropy_context entropy_context;
mbedtls_x509_crt cert_chain1;
mbedtls_x509_crt cert_chain2;
mbedtls_x509_crt cert_chain3;
mbedtls_pk_context key_pair;

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_init(JNIEnv *, jobject);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setupSSLContext(JNIEnv *, jobject);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setIOFuncs(JNIEnv *, jobject, jstring);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getClassObject(JNIEnv *, jobject, jobject);
JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_executeNextHandshakeStep(JNIEnv *, jobject);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_configureCipherSuites(JNIEnv *, jobject, jintArray);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setMinimumProtocolVersion(JNIEnv *, jobject, jint);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setMaximumProtocolVersion(JNIEnv *, jobject, jint);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_enableDebug(JNIEnv *, jobject, jint);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_configureClientCert(JNIEnv *, jobject, jbyteArray, jbyteArray);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_configureRootCACert(JNIEnv *, jobject, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getIssuerName(JNIEnv *, jobject, jbyteArray);
JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_fixPeerCert(JNIEnv *, jobject);

#endif //MBEDTLS_ANDROID_LIBMBEDTLS_H
