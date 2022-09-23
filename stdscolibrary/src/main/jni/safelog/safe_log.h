//
// Created by 80349693 on 2021/8/20.
//

#ifndef SAFE_LOG_H
#define SAFE_LOG_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void safe_log_init(JNIEnv *env, jclass clazz, jint jlevel, jstring jtag);

#ifdef __cplusplus
}
#endif


#endif //SAFE_LOG_H
