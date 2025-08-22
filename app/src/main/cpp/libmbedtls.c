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
} mbedtls_client_impl_t;

jobject classReference;
jmethodID alWriteCallback;
jmethodID alReadCallback;
jmethodID alDebug;
jmethodID debugUtility;
mbedtls_client_impl_t *impl;

static JavaVM *jvm;

//jintArray ciphers;

#define _LOG_TAG "AL_MbedTLS"
#define LOG_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, _LOG_TAG, __VA_ARGS__)
#define LOG_WARN(...) __android_log_print(ANDROID_LOG_WARN, _LOG_TAG, __VA_ARGS__)
#define LOG_INFO(...) __android_log_print(ANDROID_LOG_INFO, _LOG_TAG, __VA_ARGS__)
#define LOG_DEBUG(...) __android_log_print(ANDROID_LOG_DEBUG, _LOG_TAG, __VA_ARGS__)
//
//JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_init(JNIEnv *env, jobject thisObj) {
//    mbedtls_ssl_init(&ssl_context);
//    mbedtls_ssl_config_init(&ssl_config);
//    mbedtls_ctr_drbg_init(&random_byte_generator);
//    mbedtls_entropy_init(&entropy_context);
//    mbedtls_x509_crt_init(&cert_chain1);
//    mbedtls_x509_crt_init(&cert_chain2);
//    mbedtls_x509_crt_init(&cert_chain3);
//    mbedtls_pk_init(&key_pair);
//
//    int ret = mbedtls_ctr_drbg_seed(&random_byte_generator, mbedtls_entropy_func, &entropy_context, NULL, 0);
//    if (ret != 0) {
//        return SS_MBEDTLS_ERR_ENTROPY;
//    }
//
//    //Cache JavaVM pointer
//    (*env)->GetJavaVM(env, &jvm);
//
//    return ret;
//}
//
//JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_setupSSLContextNative(JNIEnv *env, jobject thisObj) {
//    int configureSSL = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
//                                                   MBEDTLS_SSL_PRESET_DEFAULT);
//    if (configureSSL != 0) {
//        return SS_MBEDTLS_ERR_SSL_CONFIG;
//    }
//
//    mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &random_byte_generator);
//
//    int setupSSL = mbedtls_ssl_setup(&ssl_context, &ssl_config);
//    if (setupSSL != 0) {
//        return SS_MBEDTLS_ERR_SSL_SETUP;
//    }
//
//    return 0;
//}

JNIEXPORT void JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_getClassObject(JNIEnv *env, jobject thisObj, jobject classref) {
    classReference = (*env)->NewGlobalRef(env, classref);
    jclass mbedTLS = (*env)->GetObjectClass(env, classref);
    alReadCallback = (*env)->GetMethodID(env, mbedTLS, "read", "([BI)I");
    alWriteCallback = (*env)->GetMethodID(env, mbedTLS, "write", "([BI)I");
    alDebug = (*env)->GetMethodID(env, mbedTLS, "alDebug", "(I[CI[C)V");
    debugUtility = (*env)->GetMethodID(env, mbedTLS, "debugUtility", "([BI[B)V");
}
int write_callback(void *ctx, const unsigned char *buf, size_t len) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize) len, (jbyte *) buf);

    LOG_INFO("Begin Write");
    jint result = (*env)->CallIntMethod(env, classReference, alWriteCallback, arr, (jint) len);
    LOG_INFO("End Write: %d", result);
    return result;
}

int read_callback(void *ctx, unsigned char *buf, size_t len) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize) len, (jbyte *) buf);
    LOG_INFO("Begin Read");
    jint bytesRead = (*env)->CallIntMethod(env, classReference, alReadCallback, arr, (jint) len);
    LOG_INFO("End Read: %d", bytesRead);
//    (*env)->GetByteArrayRegion(env, bytesToRead, 0, (jsize)len, (jbyte*)buf);
    return (int) bytesRead;
}
//
//JNIEXPORT void JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_setIOFuncs(JNIEnv *env, jobject thisObj, jstring contextParameter) {
//    mbedtls_ssl_set_bio(&ssl_context, &contextParameter,
//                        (int (*)(void *, const unsigned char *, size_t)) write_callback,
//                        (int (*)(void *, unsigned char *, size_t)) read_callback, NULL);
//}
//
//JNIEXPORT void JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_configureCipherSuites(JNIEnv *env, jobject thisObj, jintArray ciphersuites) {
//    ciphers = (*env)->GetIntArrayElements(env, ciphersuites, 0);
//    mbedtls_ssl_conf_ciphersuites(&ssl_config, ciphers);
//}
//
//JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_configurePsk(
//        JNIEnv *env,
//        jobject thisObj,
//        jcharArray pskId,
//        jint pskIdLength,
//        jbyteArray pskSecret,
//        jint pskSecretLength
//) {
//    mbedtls_ssl_conf_psk(&ssl_config, pskId, pskIdLength, pskSecret, pskSecretLength);
//}
//
//JNIEXPORT void JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_setMinimumProtocolVersion(JNIEnv *env, jobject thisObj, jint version) {
//    mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, version);
//}
//
//JNIEXPORT void JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_setMaximumProtocolVersion(JNIEnv *env, jobject thisObj, jint version) {
//    mbedtls_ssl_conf_max_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, version);
//}
//
//JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_executeHandshakeStep(JNIEnv *env, jobject thisObj) {
//    int ret = mbedtls_ssl_handshake_step(&ssl_context);
////    if (ret != 0) {
////        return SS_MBEDTLS_ERR_HANDSHAKE_STEP;
////    }
//    return ret;
//}
//
//JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getCurrentHandshakeState(JNIEnv *env, jobject thisObj) {
//    return ssl_context.state;
//}
//
//int get_array_size(const char *arr) {
//    int size = 0;
//    while (arr[size] != '\0') size++;
//    return size;
//}
//
void debug_msg(void *ctx, int level, const char *file, int line, const char *str) {
    LOG_INFO("%s", str);
//    JNIEnv *env;
//    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
//    jbyteArray fileName = (*env)->NewByteArray(env, get_array_size(file));
//    (*env)->SetByteArrayRegion(env, fileName, 0, (jsize) get_array_size(file), (jbyte *) file);
//    jbyteArray log = (*env)->NewByteArray(env, get_array_size(str));
//    (*env)->SetByteArrayRegion(env, log, 0, (jsize) get_array_size(str), (jbyte *) str);
//    (*env)->CallVoidMethod(env, classReference, debugUtility, fileName, line, log);
}
//
//JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_enableDebug(JNIEnv *env, jobject thisObj, jint level) {
//    mbedtls_debug_set_threshold(level);
//    mbedtls_ssl_conf_dbg(&ssl_config, debug_msg, stdout);
//}
//
//JNIEXPORT jint
//Java_com_simplisafe_mbedtls_MbedTLS_configureClientCertNative(JNIEnv *env, jobject thisObj, jbyteArray certificateBytes,
//                                                              jbyteArray keyPair) {
//    int cert_len = (*env)->GetArrayLength(env, certificateBytes);
//    int key_pair_len = (*env)->GetArrayLength(env, keyPair);
//    jbyte *certificate = (*env)->GetByteArrayElements(env, certificateBytes, NULL);
//    jbyte *privateKey = (*env)->GetByteArrayElements(env, keyPair, NULL);
//    if (mbedtls_x509_crt_parse(&cert_chain1, (unsigned char *) certificate, (size_t) cert_len) != 0) {
//        return SS_MBEDTLS_ERR_PARSE_CERT;
//    }
//    if (mbedtls_pk_parse_key(&key_pair, (unsigned char *) privateKey, (size_t) key_pair_len, NULL, 0) != 0) {
//        return SS_MBEDTLS_ERR_PARSE_KEY;
//    }
//    if (mbedtls_ssl_conf_own_cert(&ssl_config, &cert_chain1, &key_pair) != 0) {
//        return SS_MBEDTLS_ERR_CONFIG_CLIENT_CERT;
//    }
//    (*env)->ReleaseByteArrayElements(env, certificateBytes, certificate, 0);
//    (*env)->ReleaseByteArrayElements(env, keyPair, privateKey, 0);
//    return 0;
//}
//
//JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_configureRootCACertNative(JNIEnv *env, jobject thisObj,
//                                                                                     jbyteArray certificateBytes) {
//    int len = (*env)->GetArrayLength(env, certificateBytes);
//    jbyte *certificate = (*env)->GetByteArrayElements(env, certificateBytes, NULL);
//    if (mbedtls_x509_crt_parse(&cert_chain2, (unsigned char *) certificate, (size_t) len) == 0) {
//        mbedtls_ssl_conf_ca_chain(&ssl_config, &cert_chain2, NULL);
//        (*env)->ReleaseByteArrayElements(env, certificateBytes, certificate, 0);
//        return 0;
//    } else {
//        (*env)->ReleaseByteArrayElements(env, certificateBytes, certificate, 0);
//        return SS_MBEDTLS_ERR_PARSE_CERT;
//    }
//}
//
//mbedtls_x509_name *get_common_name(mbedtls_x509_name *subject) {
//    mbedtls_x509_name *data = subject;
//    /*
//    * Gets the subject attributes of the certs and iterates through pointers to get to the common name attribute.
//    * OID for the CN object is 0x55 0x04 0x03 (85 04 03)
//    */
//    while (data != NULL) {
//        if ((data->oid.p[0] == 0x55) &&
//            (data->oid.p[1] == 0x04) &&
//            (data->oid.p[2] == 0x03)) {
//            return data;
//        }
//        data = data->next;
//    }
//    return NULL;
//}
//
//JNIEXPORT jbyteArray JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_getIssuerNameNative(JNIEnv *env, jobject thisObj, jbyteArray certificateBytes) {
//    int len = (*env)->GetArrayLength(env, certificateBytes);
//    jbyte *certificate = (*env)->GetByteArrayElements(env, certificateBytes, NULL);
//    if (mbedtls_x509_crt_parse(&cert_chain3, (unsigned char *) certificate, (size_t) len) == 0) {
//        mbedtls_x509_name *issuer_name = get_common_name(&cert_chain3.issuer);
//        if (issuer_name == NULL) {
//            return NULL;
//        }
//        jbyteArray arr = (*env)->NewByteArray(env, (jsize) issuer_name->val.len);
//        (*env)->SetByteArrayRegion(env, arr, 0, (jsize) issuer_name->val.len, (jbyte *) issuer_name->val.p);
//        (*env)->ReleaseByteArrayElements(env, certificateBytes, certificate, 0);
//        return arr;
//    }
//    (*env)->ReleaseByteArrayElements(env, certificateBytes, certificate, 0);
//    return NULL;
//}
//
//JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_MbedTLS_write(JNIEnv *env, jobject thisObj, jbyteArray data) {
//    int len = (*env)->GetArrayLength(env, data);
//    jbyte *dataToWrite = (*env)->GetByteArrayElements(env, data, NULL);
//    if (mbedtls_ssl_write(&ssl_context, (unsigned char *) dataToWrite, (size_t) len) == len) {
//        (*env)->ReleaseByteArrayElements(env, data, dataToWrite, 0);
//        return JNI_TRUE;
//    }
//    return JNI_FALSE;
//}
//
//JNIEXPORT jboolean JNICALL
//Java_com_simplisafe_mbedtls_MbedTLS_read(JNIEnv *env, jobject thisObj, jint length, jbyteArray buffer) {
//    unsigned char arr[length];
//    if (mbedtls_ssl_read(&ssl_context, arr, (size_t) length) < 0) {
//        return JNI_FALSE;
//    } else {
//        (*env)->SetByteArrayRegion(env, buffer, 0, (jsize) length, (jbyte *) arr);
//        return JNI_TRUE;
//    }
//}




JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_deallocateClient(mbedtls_client_handle_t handle) {
    mbedtls_client_impl_t *impl = handle;
    mbedtls_ssl_free(&impl->context);
    mbedtls_ctr_drbg_free(&impl->ctr_drbg);
    mbedtls_entropy_free(&impl->entropy);
    mbedtls_ssl_config_free(&impl->config);
    free(impl->cipher_suites);
    free(impl);
    impl = NULL;
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_MbedTLS_initClientImpl(
        JNIEnv *env,
        jobject thisObj,
        jint transport,
        jintArray cipher_suites,
        jint num_cipher_suites,
        jbyteArray psk,
        jint psk_len,
        jcharArray psk_id,
        jint psk_id_len,
        void *io_context
) {
    (*env)->GetJavaVM(env, &jvm);
    int err_out = 0;
    LOG_INFO("==>Start\n");
    jint* ciphers = (*env)->GetIntArrayElements(env, cipher_suites, 0);

    impl = malloc(sizeof(mbedtls_client_impl_t));
    memset(impl, 0, sizeof(*impl));
    impl->cipher_suites = calloc(num_cipher_suites + 1, sizeof(int));
    memcpy(impl->cipher_suites, ciphers, num_cipher_suites * sizeof(int));
    impl->cipher_suites[num_cipher_suites] = 0;

//    jchar *carr = malloc(psk_id_len * sizeof(jchar));

    //     (*env)->SetByteArrayRegion(env, arr, 0, (jsize) len, (jbyte *) buf);
    jchar buf[psk_id_len + 1] = {};
    (*env)->GetCharArrayRegion(env, psk_id, 0, psk_id_len, buf);

    LOG_INFO("==>SSL INIT %d", impl->cipher_suites[0]);
    mbedtls_ssl_init(&impl->context);
    LOG_INFO("==>SSL CONFIG\n");
    mbedtls_ssl_config_init(&impl->config);
    LOG_INFO("==>DRBG INIT\n");
    mbedtls_ctr_drbg_init(&impl->ctr_drbg);
    LOG_INFO("==>ENTROPY INIT\n");
    mbedtls_entropy_init(&impl->entropy);

    if (mbedtls_ctr_drbg_seed(&impl->ctr_drbg, mbedtls_entropy_func, &impl->entropy, NULL, 0)) {
        LOG_INFO("==>mbedtls_ctr_drbg_seed failed! deallocating\n");
        Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_deallocateClient(impl);
        return;
    }

    if (mbedtls_ssl_config_defaults(&impl->config, MBEDTLS_SSL_IS_CLIENT, transport,
                                                MBEDTLS_SSL_PRESET_DEFAULT)) {
        LOG_INFO("==>mbedtls_ssl_config_defaults failed! deallocating\n");
        Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_deallocateClient(impl);
        return;
    }

    LOG_INFO("==>RNG\n");
    mbedtls_ssl_conf_rng(&impl->config, mbedtls_ctr_drbg_random, &impl->ctr_drbg);
    LOG_INFO("==>CIPHERSUITES\n");
    mbedtls_ssl_conf_ciphersuites(&impl->config, impl->cipher_suites);

    if (mbedtls_ssl_conf_psk(&impl->config, psk, psk_len, (const uint8_t *) psk_id, psk_id_len)) {
        Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_deallocateClient(impl);
        return;
    }

    LOG_INFO("==>debug set threshold\n");
    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_dbg(&impl->config, debug_msg, NULL);

    if (mbedtls_ssl_setup(&impl->context, &impl->config)) {
        Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_deallocateClient(impl);
        return;
    }

    LOG_INFO("==>set timer\n");
    mbedtls_ssl_set_timer_cb(&impl->context, &impl->timing, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

    LOG_INFO("==>set callbacks\n");
    mbedtls_ssl_set_bio(
            &impl->context,
            io_context,
            write_callback,
            read_callback,
            NULL
    );

    LOG_INFO("==>end et callbacks\n");

    return;
}
JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_MbedTLS_initClientHandshake(
        JNIEnv *env,
        jobject thisObj) {
//    mbedtls_client_impl_t *impl = handle;
    return mbedtls_ssl_handshake(&impl->context);
}

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_client_write(
        JNIEnv *env,
        jobject thisObj,
        jbyteArray *data,
        jint length) {
//    mbedtls_client_impl_t *impl = handle;
    return mbedtls_ssl_write(&impl->context, data, length);
}

JNIEXPORT jint JNICALL
Java_com_simplisafe_mbedtls_MbedTLS_al_mbedtls_client_read(
        JNIEnv *env,
        jobject thisObj,
        jbyteArray *data,
        jint length) {
//    mbedtls_client_impl_t *impl = handle;
    return mbedtls_ssl_read(&impl->context, data, length);
}
