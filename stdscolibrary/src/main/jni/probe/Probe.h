
#ifndef PROBE_H_
#define PROBE_H_

#include <jni.h>
#include <string>
#include "CJsonObject.h"
using namespace std;

#define OINT long
#ifdef __LP64__
#define OINT long
#endif

class Probe {
public:
    Probe(JNIEnv *_env,jobject _context);
    ~Probe();
    string getProbeResult();

private:
    void report();
    void report(const char* key, const char* value);
    CJsonObject probeJson;
    JNIEnv *env;
    jobject context;

    void checkAll();
    bool JniExceptionCheck();
    void checkRoot();
    void checkSelinux();
    void checkXposed();
    void checkMulti();
    void checkProxy();
    void checkVpn();
    void checkMaps();
    void checkPtrace();
    void checkEmulator();
    void findMemFrida(OINT base, OINT end, char* path);
    void findMemHook(OINT base, OINT end, OINT offset, char* path);
    void findMemBreakpoint(OINT base, OINT end, OINT offset, char* path);
};

jstring getProbeRespStr(JNIEnv* env, jobject obj, jobject ctx);

#endif  /* PROBE_H_ */
