//
// Created by W9012116 on 2021/8/23.
//

#ifndef STDSCO_AUTH_H
#define STDSCO_AUTH_H
#include <string>
#include "probe/CJsonObject.h"

#define __USE_ONEWAY_CERTIFICATION__        0
#define __USE_JNI_ENCRYPT__                 0

#define JNI_VERSION                         JNI_VERSION_1_6
#define AUTH_VERNO                          "1.0.0"

#define AES_KEY_LENGTH                      ( 256 / 8)
#define RSA_LENGTH                          ( 2048 / 8 )
#define RSA_PRIVATE_KEY_LENGTH              ( 1190 )
#define RSA_PUBLIC_KEY_LENGTH               ( 294 )

extern char *g_appId_c;
extern char *g_oppoSign_c;

void auth_init(JNIEnv *env, jclass clazz, jobject context, jstring appId);

std::string get_service_data(const char* serviceId, const char* param);

#if __USE_ONEWAY_CERTIFICATION__
int get_open_ca_size();
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool auth_service(const char* serviceId);

#ifdef __cplusplus
}
#endif

#endif //STDSCO_AUTH_H
