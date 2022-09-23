//
// Created by 80349693 on 2021/8/20.
//

#include <jni.h>
#include "safelog/safe_log.h"
#include "auth/auth.h"
#include "probe/Probe.h"
#include "urlcheck/url_check.h"

JavaVM *g_jvm = NULL;

#define JNI_SAFELOG_CLASS "com/oplus/omes/stdsco/safelog/StdScoLog"
#define JNI_AUTH_CLASS "com/oplus/omes/stdsco/auth/AuthClient"
#define JNI_PROBE_CLASS "com/oplus/omes/stdsco/probe/ProbeClient"
#define JNI_URLCHECK_CLASS "com/oplus/omes/stdsco/urlcheck/UrlCheckClient"

static JNINativeMethod jni_safelog_methods[] = {
        {"nativeLogInit", "(ILjava/lang/String;)V", (void *)safe_log_init }
};

static JNINativeMethod jni_auth_methods[] = {
        {"nativeAuthInit", "(Ljava/lang/Object;Ljava/lang/String;)V", (void *)auth_init }
};

static JNINativeMethod jni_probe_methods[] = {
        {"getProbeRespStr", "(Ljava/lang/Object;)Ljava/lang/String;", (void *)getProbeRespStr }
};

static JNINativeMethod jni_urlcheck_methods[] = {
        {"nativeUrlsCheck", "(Ljava/lang/String;)Ljava/lang/String;", (void *)check_urls_init }
};

static int registerNativeMethods(JNIEnv* env, const char* className,
                                 JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static int registerNatives(JNIEnv* env) {
    if (!registerNativeMethods(env, JNI_SAFELOG_CLASS, jni_safelog_methods,
                               sizeof(jni_safelog_methods) / sizeof(jni_safelog_methods[0])))
        return JNI_FALSE;

    if (!registerNativeMethods(env, JNI_AUTH_CLASS, jni_auth_methods,
                               sizeof(jni_auth_methods) / sizeof(jni_auth_methods[0])))
        return JNI_FALSE;

    if (!registerNativeMethods(env, JNI_PROBE_CLASS, jni_probe_methods,
                               sizeof(jni_probe_methods) / sizeof(jni_probe_methods[0])))
        return JNI_FALSE;

    if (!registerNativeMethods(env, JNI_URLCHECK_CLASS, jni_urlcheck_methods,
                               sizeof(jni_urlcheck_methods) / sizeof(jni_urlcheck_methods[0])))
        return JNI_FALSE;

    return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    JNIEnv * env;

    if (vm->GetEnv((void**) &env, JNI_VERSION) != JNI_OK) {
        return -1;
    }

    if (!registerNatives(env)) {
        return -1;
    }
    return JNI_VERSION;
}
