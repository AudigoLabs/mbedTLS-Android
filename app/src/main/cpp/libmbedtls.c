//
// Created by Siddarth Gandhi on 2019-05-10.
//

#include <jni.h>
#include <string.h>
#include <assert.h>
#include "libmbedtls.h"
#include "mbedtls/debug.h"

jobject classReference;
jmethodID writeCallback;
jmethodID readCallback;
jmethodID debugUtility;

static JavaVM *jvm;

jintArray ciphers;

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_init(JNIEnv *env, jobject thisObj) {
    mbedtls_ssl_init(&ssl_context);
    mbedtls_ssl_config_init(&ssl_config);
    mbedtls_ctr_drbg_init(&random_byte_generator);
    mbedtls_entropy_init(&entropy_context);
    mbedtls_x509_crt_init(&cert_chain1);
    mbedtls_x509_crt_init(&cert_chain2);
    mbedtls_x509_crt_init(&cert_chain3);
    mbedtls_pk_init(&key_pair);

    int ret = mbedtls_ctr_drbg_seed(&random_byte_generator, mbedtls_entropy_func, &entropy_context, NULL, 0);
    if (ret != 0) {
        return SS_MBEDTLS_ERR_ENTROPY;
    }

    //Cache JavaVM pointer
    (*env)->GetJavaVM(env, &jvm);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setupSSLContextNative(JNIEnv *env, jobject thisObj) {
    int configureSSL = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (configureSSL != 0) {
        return SS_MBEDTLS_ERR_SSL_CONFIG;
    }

    mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &random_byte_generator);

    int setupSSL = mbedtls_ssl_setup(&ssl_context, &ssl_config);
    if (setupSSL != 0) {
        return SS_MBEDTLS_ERR_SSL_SETUP;
    }

    return 0;
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getClassObject(JNIEnv *env, jobject thisObj, jobject classref) {
    classReference = (*env)->NewGlobalRef(env, classref);
    jclass mbedTLS = (*env)->GetObjectClass(env, classref);
    writeCallback = (*env)->GetMethodID(env, mbedTLS, "writeCallback", "([BI)I");
    readCallback = (*env)->GetMethodID(env, mbedTLS, "readCallback", "(I)[B");
    debugUtility = (*env)->GetMethodID(env, mbedTLS, "debugUtility", "([BI[B)V");
}

int write_callback(void *ctx, const unsigned char *buf, size_t len) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (jbyte*)buf);
    jint result = (*env)->CallIntMethod(env, classReference, writeCallback, arr, len);
    return result;
}

int read_callback(void *ctx, unsigned char *buf, size_t len) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray bytesToRead = (*env)->CallObjectMethod(env, classReference, readCallback, len);
    (*env)->GetByteArrayRegion(env, bytesToRead, 0, (jsize)len, (jbyte*)buf);
    return (int)len;
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setIOFuncs(JNIEnv *env, jobject thisObj, jstring contextParameter) {
    mbedtls_ssl_set_bio(&ssl_context, &contextParameter, write_callback, read_callback, NULL);
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_configureCipherSuites(JNIEnv *env, jobject thisObj, jintArray ciphersuites) {
    ciphers = (*env)->GetIntArrayElements(env, ciphersuites, 0);
    mbedtls_ssl_conf_ciphersuites(&ssl_config, ciphers);
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setMinimumProtocolVersion(JNIEnv *env, jobject thisObj, jint version) {
    mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, version);
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_setMaximumProtocolVersion(JNIEnv *env, jobject thisObj, jint version) {
    mbedtls_ssl_conf_max_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, version);
}

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_executeHandshakeStep(JNIEnv *env, jobject thisObj) {
    int ret = mbedtls_ssl_handshake_client_step(&ssl_context);
    if (ret != 0) {
        return SS_MBEDTLS_ERR_HANDSHAKE_STEP;
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getCurrentHandshakeState(JNIEnv *env, jobject thisObj) {
    return ssl_context.state;
}

int get_array_size(const char *arr) {
    int size = 0;
    while (arr[size] != '\0') size++;
    return size;
}

void debug_msg(void *ctx, int level, const char *file, int line, const char *str) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jbyteArray fileName = (*env)->NewByteArray(env, get_array_size(file));
    (*env)->SetByteArrayRegion(env, fileName, 0, (jsize)get_array_size(file), (jbyte*)file);
    jbyteArray log = (*env)->NewByteArray(env, get_array_size(str));
    (*env)->SetByteArrayRegion(env, log, 0, (jsize)get_array_size(str), (jbyte*)str);
    (*env)->CallVoidMethod(env, classReference, debugUtility, fileName, line, log);
}

JNIEXPORT void JNICALL Java_com_simplisafe_mbedtls_mbedTLS_enableDebug(JNIEnv *env, jobject thisObj, jint level) {
    mbedtls_debug_set_threshold(level);
    mbedtls_ssl_conf_dbg(&ssl_config, debug_msg, stdout);
}

JNIEXPORT jint Java_com_simplisafe_mbedtls_mbedTLS_configureClientCertNative(JNIEnv *env, jobject thisObj, jbyteArray certificateBytes, jbyteArray keyPair) {
    int cert_len = (*env)->GetArrayLength(env, certificateBytes);
    int key_pair_len = (*env)->GetArrayLength(env, keyPair);
    unsigned char* certificate = (unsigned char*)(*env)->GetByteArrayElements(env, certificateBytes, NULL);
    unsigned char* privateKey = (unsigned char*)(*env)->GetByteArrayElements(env, keyPair, NULL);
    if (mbedtls_x509_crt_parse(&cert_chain1, certificate, (size_t)cert_len) != 0) {
        return SS_MBEDTLS_ERR_PARSE_CERT;
    }
    if (mbedtls_pk_parse_key(&key_pair, privateKey, (size_t)key_pair_len, NULL, 0) != 0) {
        return SS_MBEDTLS_ERR_PARSE_KEY;
    }
    if (mbedtls_ssl_conf_own_cert(&ssl_config, &cert_chain1, &key_pair) != 0) {
        return SS_MBEDTLS_ERR_CONFIG_CLIENT_CERT;
    }
    return 0;
}

JNIEXPORT jint JNICALL Java_com_simplisafe_mbedtls_mbedTLS_configureRootCACertNative(JNIEnv *env, jobject thisObj, jbyteArray certificateBytes) {
    int len = (*env)->GetArrayLength(env, certificateBytes);
    unsigned char* certificate = (unsigned char*)(*env)->GetByteArrayElements(env, certificateBytes, NULL);
    if (mbedtls_x509_crt_parse(&cert_chain2, certificate, (size_t)len) == 0) {
        mbedtls_ssl_conf_ca_chain(&ssl_config, &cert_chain2, NULL);
        return 0;
    } else {
        return SS_MBEDTLS_ERR_PARSE_CERT;
    }
}

mbedtls_x509_name* get_common_name(mbedtls_x509_name *subject) {
    mbedtls_x509_name *data = subject;
    /*
    * Gets the subject attributes of the certs and iterates through pointers to get to the common name attribute.
    * OID for the CN object is 0x55 0x04 0x03 (85 04 03)
    */
    while (data != NULL) {
        if ( (data->oid.p[0] == 0x55) &&
                (data->oid.p[1] == 0x04) &&
                (data->oid.p[2] == 0x03) ) {
            return data;
        }
        data = data->next;
    }
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_com_simplisafe_mbedtls_mbedTLS_getIssuerNameNative(JNIEnv *env, jobject thisObj, jbyteArray certificateBytes) {
    int len = (*env)->GetArrayLength(env, certificateBytes);
    unsigned char* certificate = (unsigned char*)(*env)->GetByteArrayElements(env, certificateBytes, NULL);
    if (mbedtls_x509_crt_parse(&cert_chain3, certificate, (size_t)len) == 0) {
        mbedtls_x509_name* issuer_name = get_common_name(&cert_chain3.issuer);
        if (issuer_name == NULL) {
            return NULL;
        }
        jbyteArray arr = (*env)->NewByteArray(env, (jsize)issuer_name->val.len);
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)issuer_name->val.len, (jbyte*)issuer_name->val.p);
        return arr;
    }
    return NULL;
}

JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_mbedTLS_fixPeerCert(JNIEnv *env, jobject thisObj, jstring commonName) {
    mbedtls_x509_crt *cert = ssl_context.session_negotiate->peer_cert;
    while (cert != NULL) {
        mbedtls_x509_name* common_name = get_common_name(&cert->subject);
        if (common_name == NULL) {
            return JNI_FALSE;
        }
        jsize stringLength = (*env)->GetStringUTFLength(env, commonName);
        const char *str = (*env)->GetStringUTFChars(env, commonName, 0);
        int ret = strncmp((const char*)common_name->val.p, str, (size_t)stringLength);

        if (ret == 0) {
            ssl_context.session_negotiate->peer_cert = cert;
            return JNI_TRUE;
        }
        cert = cert->next;
    }
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_mbedTLS_write(JNIEnv *env, jobject thisObj, jbyteArray data) {
    int len = (*env)->GetArrayLength(env, data);
    unsigned char* dataToWrite = (unsigned char*)(*env)->GetByteArrayElements(env, data, NULL);
    if (mbedtls_ssl_write(&ssl_context, dataToWrite, (size_t)len) == len) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_simplisafe_mbedtls_mbedTLS_read(JNIEnv *env, jobject thisObj, jint length, jbyteArray buffer) {
    unsigned char arr[length];
    if (mbedtls_ssl_read(&ssl_context, arr, (size_t)length) < 0) {
        return JNI_FALSE;
    } else {
        (*env)->SetByteArrayRegion(env, buffer, 0, (jsize)length, (jbyte*)arr);
        return JNI_TRUE;
    }
}