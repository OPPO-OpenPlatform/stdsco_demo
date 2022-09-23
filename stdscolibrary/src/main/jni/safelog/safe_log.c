//
// Created by 80349693 on 2021/8/16.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <stdint.h>
#include <regex.h>
#include <inttypes.h>
#include <string.h>
#include <dlfcn.h>
#include <jni.h>
#include <sys/time.h>
#include <android/log.h>
#include "bytehook.h"
#include "bh_core.h"
#include "bh_log.h"

extern bool auth_service(const char* serviceId);

typedef int (*log_buf_write_t)(int bufID, int prio, const char* tag, const char* msg);
typedef int (*log_buf_print_t)(int bufID, int prio, const char* tag, const char* fmt, ...);
typedef int (*log_vprint_t)(int prio, const char* tag, const char* fmt, va_list ap);
typedef int (*log_print_t)(int prio, const char* tag, const char* fmt, ...);
typedef int (*log_write_t)(int prio, const char* tag, const char* text);

#define HOOK_FUNC_DEF(fn) \
static fn##_t fn##_prev = NULL; \
static void* fn##_stub = NULL; \
static void fn##_hooked_callback(bytehook_stub_t task_stub, int status_code, const char *caller_path_name, const char *sym_name, void *new_func, void *prev_func, void *arg) \
{ \
    fn##_prev = (fn##_t)prev_func; \
    BH_LOG_INFO(">>>>> hooked. stub: %" PRIxPTR", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR", prev_func: %" PRIxPTR", arg: %" PRIxPTR, \
        (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func, (uintptr_t)prev_func, (uintptr_t)arg); \
}

#define HOOK_FUNC_START(fn, fn_sym_str) \
if(fn##_stub == NULL) \
{ \
    void* fn##_proxy = (void *)fn##_proxy_auto; \
    fn##_stub = bytehook_hook_all(NULL, fn_sym_str, fn##_proxy, fn##_hooked_callback, NULL); \
}

HOOK_FUNC_DEF(log_buf_write)
HOOK_FUNC_DEF(log_buf_print)
HOOK_FUNC_DEF(log_vprint)
HOOK_FUNC_DEF(log_print)
HOOK_FUNC_DEF(log_write)

static int s_log_level = 0;
static regex_t s_log_tag_reg;
static bool inited = false;

static void* safe_log_hacker(void *arg);

void safe_log_init(JNIEnv *env, jclass clazz, jint jlevel, jstring jtag)
{
    (void)clazz;
    s_log_level = jlevel;
    const char *tag = (*env)->GetStringUTFChars(env, jtag, NULL);
    if(0 != regcomp(&s_log_tag_reg, tag, REG_NOSUB | REG_EXTENDED))
    {
        BH_LOG_SHOW("the regular expression is incorrect!");
        return;
    }
    (*env)->ReleaseStringUTFChars(env, jtag, tag);

    if (inited)
        return;
    inited = true;

    pthread_t tid;
    pthread_create(&tid, NULL, &safe_log_hacker, NULL);
}

static bool safe_log_filter(int level, const char* tag)
{
    if (!tag)
        tag = "";

    if(0 != regexec(&s_log_tag_reg, tag, 0, NULL, 0))
        return false;

    if(level > s_log_level)
        return false;

    return true;
}

static int log_buf_write_proxy_auto(int bufID, int prio, const char* tag, const char* msg)
{
    int ret = 1;
    log_buf_write_t func = (log_buf_write_t)bytehook_get_prev_func((void *)(log_buf_write_proxy_auto));
    if(!safe_log_filter(prio, tag))
        ret = func(bufID, prio, tag, msg);
    BYTEHOOK_RETURN_ADDRESS();
    BYTEHOOK_POP_STACK();
    return ret;
}

static int log_buf_print_proxy_auto(int bufID, int prio, const char* tag, const char* fmt, ...)
{
    int ret = 1;
    log_buf_print_t func = (log_buf_print_t)bytehook_get_prev_func((void *)(log_buf_print_proxy_auto));
    if(!safe_log_filter(prio, tag))
    {
        va_list ap;
        __attribute__((uninitialized)) char buf[1024];
        va_start(ap, fmt);
        vsnprintf(buf, 1024, fmt, ap);
        va_end(ap);
        __android_log_buf_write(bufID, prio, tag, buf);
    }
    BYTEHOOK_RETURN_ADDRESS();
    BYTEHOOK_POP_STACK();
    return ret;
}

static int log_vprint_proxy_auto(int prio, const char* tag, const char* fmt, va_list ap)
{
    int ret = 1;
    log_vprint_t func = (log_vprint_t)bytehook_get_prev_func((void *)(log_vprint_proxy_auto));
    if(!safe_log_filter(prio, tag))
        ret = func(prio, tag, fmt, ap);
    BYTEHOOK_RETURN_ADDRESS();
    BYTEHOOK_POP_STACK();
    return ret;
}

static int log_print_proxy_auto(int prio, const char* tag, const char* fmt, ...)
{
    int ret = 1;
    log_print_t func = (log_print_t)bytehook_get_prev_func((void *)(log_print_proxy_auto));
    if(!safe_log_filter(prio, tag))
    {
        va_list ap;
        va_start(ap, fmt);
        __android_log_vprint(prio, tag, fmt, ap);
        va_end(ap);
    }
    BYTEHOOK_RETURN_ADDRESS();
    BYTEHOOK_POP_STACK();
    return ret;
}

static int log_write_proxy_auto(int prio, const char* tag, const char* text)
{
    int ret = 1;
    log_write_t func = (log_buf_write_t)bytehook_get_prev_func((void *)(log_write_proxy_auto));
    if(!safe_log_filter(prio, tag))
        ret = func(prio, tag, text);
    BYTEHOOK_RETURN_ADDRESS();
    BYTEHOOK_POP_STACK();
    return ret;
}

static void* safe_log_hacker(void *arg)
{

    bool isAuth = auth_service("LogSafe");
    if(isAuth == false)
        return NULL;

    //初始化bHook
    if(bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false) != 0)
        return NULL;

    //开始hook
    HOOK_FUNC_START(log_buf_write, "__android_log_buf_write")
    HOOK_FUNC_START(log_buf_print, "__android_log_buf_print")
    HOOK_FUNC_START(log_vprint, "__android_log_vprint")
    HOOK_FUNC_START(log_print, "__android_log_print")
    HOOK_FUNC_START(log_write, "__android_log_write")
    return NULL;
}

