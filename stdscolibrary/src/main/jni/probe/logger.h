#ifndef LOGGER_H
#define LOGGER_H

#include <android/log.h>
#include <jni.h>
#include <time.h>

#define DEBUG 1
#define TAG "SCORPION"
#define  CLOCKS_PER_SEC  ((clock_t)1000)
extern int g_sdk_int;

#if DEBUG
#  define LOGD(format, ...) __android_log_print(ANDROID_LOG_DEBUG, TAG, format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#  define LOGI(format, ...) __android_log_print(ANDROID_LOG_INFO, TAG, format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#  define LOGW(format, ...) __android_log_print(ANDROID_LOG_WARN, TAG, format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#  define LOGE(format, ...) __android_log_print(ANDROID_LOG_ERROR, TAG, format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
// #  define LOGF(format, ...) __android_log_print(ANDROID_LOG_FATAL, TAG, format "\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#else
#  define LOGD(...) while(0){;}
#  define LOGI(...) while(0){;}
#  define LOGW(...) while(0){;}
#  define LOGE(...) while(0){;}
// #  define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__)
#endif

#endif //LOGGER_H
