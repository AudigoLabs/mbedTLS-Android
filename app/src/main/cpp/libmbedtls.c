//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include <jni.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "libmbedtls.h"
#include "mbedtls/debug.h"
#include <android/log.h>

_Static_assert(MBEDTLS_CLIENT_READ_SIZE == MBEDTLS_SSL_IN_CONTENT_LEN, "");

typedef struct {
    int *cipher_suites;
    struct mbedtls_ssl_context context;
    struct mbedtls_ssl_config config;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_entropy_context entropy;
    struct mbedtls_timing_delay_context timing;
    jmethodID alReadCallback;
    jmethodID alWriteCallback;
    jobject classReference;
} mbedtls_client_impl_t;

static JavaVM *jvm;

#define _LOG_TAG "AL_MbedTLS"
#define LOG_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, _LOG_TAG, __VA_ARGS__)
#define LOG_WARN(...) __android_log_print(ANDROID_LOG_WARN, _LOG_TAG, __VA_ARGS__)
#define LOG_INFO(...) __android_log_print(ANDROID_LOG_INFO, _LOG_TAG, __VA_ARGS__)
#define LOG_DEBUG(...) __android_log_print(ANDROID_LOG_DEBUG, _LOG_TAG, __VA_ARGS__)

static void freeImpl(mbedtls_client_impl_t *impl) {
    mbedtls_ssl_free(&impl->context);
    mbedtls_ctr_drbg_free(&impl->ctr_drbg);
    mbedtls_entropy_free(&impl->entropy);
    mbedtls_ssl_config_free(&impl->config);
    free(impl->cipher_suites);
    free(impl);
}

static int write_callback(void *ctx, const unsigned char *buf, size_t len) {
    mbedtls_client_impl_t *impl = ctx;
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize) len, (jbyte *) buf);

    jint result = (*env)->CallIntMethod(env, impl->classReference, impl->alWriteCallback, arr, (jint) len);

    (*env)->DeleteLocalRef(env, arr);

    return result;
}

static int read_callback(void *ctx, unsigned char *buf, size_t len) {
    JNIEnv *env;
    mbedtls_client_impl_t *impl = ctx;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) len);

    // call Kotlin method returning Int
    jint bytesRead = (*env)->CallIntMethod(env, impl->classReference, impl->alReadCallback, arr, (jint) len);

    if (bytesRead > 0) {
        (*env)->GetByteArrayRegion(env, arr, 0, (jsize) bytesRead, (jbyte *) buf);
    }

    (*env)->DeleteLocalRef(env, arr);
    return (int) bytesRead;
}

void debug_msg(void *ctx, int level, const char *file, int line, const char *str) {
    LOG_INFO("%s", str);
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_deallocateClient(
        JNIEnv *env,
        jobject thisObj,
        jlong handle
) {
    mbedtls_client_impl_t *impl = (mbedtls_client_impl_t *) handle;
    freeImpl(impl);
}

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
) {
    (*env)->GetJavaVM(env, &jvm);
    int err_out = 0;
    jint *ciphers = (*env)->GetIntArrayElements(env, cipher_suites, 0);

    mbedtls_client_impl_t *impl = malloc(sizeof(mbedtls_client_impl_t));
    jclass mbedTLS = (*env)->GetObjectClass(env, thisObj);

    memset(impl, 0, sizeof(*impl));
    impl->cipher_suites = calloc(num_cipher_suites + 1, sizeof(int));
    memcpy(impl->cipher_suites, ciphers, num_cipher_suites * sizeof(int));
    impl->cipher_suites[num_cipher_suites] = 0;
    impl->alReadCallback = (*env)->GetMethodID(env, mbedTLS, "read", "([BI)I");
    impl->alWriteCallback = (*env)->GetMethodID(env, mbedTLS, "write", "([BI)I");
    impl->classReference = (*env)->NewGlobalRef(env, thisObj);

    uint8_t psk_buff[psk_len] = {};
    (*env)->GetByteArrayRegion(env, psk, 0, (jsize) psk_len, (jbyte *) psk_buff);

    uint8_t psk_id_buf[psk_id_len + 1] = {};
    (*env)->GetByteArrayRegion(env, psk_id, 0, (jsize) psk_id_len, (jbyte *) psk_id_buf);

    mbedtls_ssl_init(&impl->context);
    mbedtls_ssl_config_init(&impl->config);
    mbedtls_ctr_drbg_init(&impl->ctr_drbg);
    mbedtls_entropy_init(&impl->entropy);

    if (mbedtls_ctr_drbg_seed(&impl->ctr_drbg, mbedtls_entropy_func, &impl->entropy, NULL, 0)) {
        freeImpl(impl);
        return 0;
    }

    if (mbedtls_ssl_config_defaults(&impl->config, MBEDTLS_SSL_IS_CLIENT, transport,
                                    MBEDTLS_SSL_PRESET_DEFAULT)) {
        freeImpl(impl);
        return 0;
    }

    mbedtls_ssl_conf_rng(&impl->config, mbedtls_ctr_drbg_random, &impl->ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&impl->config, impl->cipher_suites);

    if (mbedtls_ssl_conf_psk(&impl->config, psk_buff, psk_len, psk_id_buf, psk_id_len)) {
        freeImpl(impl);
        return 0;
    }

    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_dbg(&impl->config, debug_msg, NULL);

    if (mbedtls_ssl_setup(&impl->context, &impl->config)) {
        freeImpl(impl);
        return 0;
    }

    mbedtls_ssl_set_timer_cb(&impl->context, &impl->timing, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

    mbedtls_ssl_set_bio(
            &impl->context,
            impl,
            write_callback,
            read_callback,
            NULL
    );

    return (jlong) impl;
}

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_initClientHandshake(
        JNIEnv *env,
        jobject thisObj,
        jlong handle
) {
    mbedtls_client_impl_t *impl = (mbedtls_client_impl_t *) handle;
    return mbedtls_ssl_handshake(&impl->context);
}

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_clientWriteNative(
        JNIEnv *env,
        jobject thisObj,
        jlong handle,
        jbyteArray data,
        jint length) {
    mbedtls_client_impl_t *impl = (mbedtls_client_impl_t *) handle;

    uint8_t buf[length] = {};
    (*env)->GetByteArrayRegion(env, data, 0, (jsize) length, (jbyte *) buf);

    return mbedtls_ssl_write(&impl->context, buf, length);
}

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_clientReadNative(
        JNIEnv *env,
        jobject thisObj,
        jlong handle,
        jbyteArray data,
        jint length) {
    mbedtls_client_impl_t *impl = (mbedtls_client_impl_t *) handle;

    uint8_t buf[length] = {};
    int bytesRead = mbedtls_ssl_read(&impl->context, buf, length);
    if (bytesRead > 0) {
        (*env)->SetByteArrayRegion(env, data, 0, bytesRead, (jbyte *) buf);
    }
    return bytesRead;
}
