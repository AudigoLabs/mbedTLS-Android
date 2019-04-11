//
// Created by Siddarth Gandhi on 4/11/19.
//

#include "testjni.h"

JNIEXPORT jstring JNICALL Java_com_simplisafe_mbedtls_MainActivity_printTest(JNIEnv *env, jobject obj) {
    jstring result = (*env)->NewStringUTF(env, "SimpliSafe");
    return result;
}