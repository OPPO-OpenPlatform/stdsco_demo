//
// Created by 80349693 on 2021/8/30.
//
#include <jni.h>
#include <string>
#include <android/log.h>
#include <sys/time.h>
#include <stdio.h>
#include <pthread.h>
#include <mutex>
#include <map>
#include "md5.h"
#include "CJsonObject.h"
#include "auth/auth.h"
#include "curl/curl.h"
#include "url_check.h"

#if 0
#define LOGD(format, ...) __android_log_print(ANDROID_LOG_DEBUG, "sco_urlcheck", format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#else
#define LOGD(...) while(0){;}
#endif

jstring check_urls_init(JNIEnv *env, jclass clazz, jstring jcontent)
{
    if(g_appId_c == NULL || g_oppoSign_c == NULL) {
        LOGD("auth is not inited!");
        return env->NewStringUTF("");
    }

    const char* content = env->GetStringUTFChars(jcontent, NULL);
    std::string data = get_service_data("URLCheck", content);
    env->ReleaseStringUTFChars(jcontent, content);

    CJsonObject resp;
    if(data.length() == 0 || resp.Parse(data) == false){
        LOGD("urls check recieved data is not a json!");
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(data.c_str());
}
