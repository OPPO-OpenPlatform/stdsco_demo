
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>                                                                                                                                
#include <fstream>
#include <vector>
#include <sys/time.h>
#include <dlfcn.h>

#include "logger.h"
#include "md5.h"
#include "Probe.h"
#include "safeApi.h"
#include "auth/auth.h"

/*const char openatBuf64[12] = {0x08, 0x07, 0x80, 0xD2, 0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6};
const char openatBuf[20] = {0x07, 0xC0, 0xA0, 0xE1, 0x42, 0x71, 0x00, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0x0C, 0x70, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1};*/

const char openatBuf64[12] = {0x09, 0x08, static_cast<char>(0x81), static_cast<char>(0xD3), 0x02, 0x01, 0x01, static_cast<char>(0xD5), static_cast<char>(0xC1), 0x04, 0x60, static_cast<char>(0xD7)};
const char openatBuf[20] = {0x08, static_cast<char>(0xC1), static_cast<char>(0xA1), static_cast<char>(0xE2), 0x43, 0x72, 0x01, static_cast<char>(0xE4), 0x01, 0x01, 0x01, static_cast<char>(0xF0), 0x0D, 0x71, static_cast<char>(0xA1), static_cast<char>(0xE2), static_cast<char>(0x1F), static_cast<char>(0xFF), 0x30, static_cast<char>(0xE2)};

int (*safe_open)(int,const char*,int);
int (*safe_openat)(int,const char*,int);
void get_safe_open();
bool file_exists(const char *path);
int exe_cmd(char* cmd,char* result);
int safe_switch = 0;

void printAddr(char* _addr){
  long tmp = (long)_addr;
  if(tmp&1==1){
    tmp -= 1;
  }
  char *addr = (char*)tmp;
  LOGE("[+]Probe open:%p %02x %02x %02x %02x %02x %02x %02x %02x",addr,addr[0],addr[1],addr[2],addr[3],addr[4],addr[5],addr[6],addr[7]);
}

string getPackageName(JNIEnv* env,jobject context){
  jclass jclazz = env->FindClass("android/app/Application");
  jmethodID mId = env->GetMethodID(jclazz, "getPackageName", "()Ljava/lang/String;");
  jstring pkg_str = (jstring)(env->CallObjectMethod(context, mId));
  char *packagename = (char *)env->GetStringUTFChars(pkg_str, NULL);

  string name(packagename);

  env->ReleaseStringUTFChars(pkg_str, packagename);
  env->DeleteLocalRef(pkg_str);
  env->DeleteLocalRef(jclazz);
  return name;
}

string createUUID(JNIEnv* env){
  jclass jclazz = env->FindClass("java/util/UUID");
  jmethodID mId = env->GetStaticMethodID(jclazz, "randomUUID", "()Ljava/util/UUID;");
  jobject jobj = env->CallStaticObjectMethod(jclazz,mId);
  mId = env->GetMethodID(jclazz, "toString", "()Ljava/lang/String;");
  jstring jstr = (jstring)env->CallObjectMethod(jobj,mId);
  char *str = (char *)env->GetStringUTFChars(jstr, NULL);
  string uuid(str);

  env->ReleaseStringUTFChars(jstr, str);
  env->DeleteLocalRef(jstr);
  env->DeleteLocalRef(jclazz);
  env->DeleteLocalRef(jobj);
  return uuid;
}

static string getTimestamp(){
  struct timeval begin;
  gettimeofday(&begin,NULL);
  long long beginTime = (long long)begin.tv_sec * 1000 + (long long)begin.tv_usec / 1000;
  char buf[64] = {0};
  sprintf(buf,"%lld",beginTime);
  return string(buf);
}



#define CLOSE_LOG 
bool Probe::JniExceptionCheck()
{
 if (env->ExceptionCheck())
 {

#ifndef CLOSE_LOG
  env->ExceptionDescribe();
#endif
  env->ExceptionClear();
  return true;
 }
 return false;
}


int getSdkInt(JNIEnv *env){
  jclass jclazz = env->FindClass("android/os/Build$VERSION");
  jfieldID SDK_INT = env->GetStaticFieldID(jclazz, "SDK_INT", "I");
  int sdkInt = env->GetStaticIntField(jclazz, SDK_INT);
  env->DeleteLocalRef(jclazz);
  return sdkInt;
}

Probe::Probe(JNIEnv *_env,jobject _context)
{
  env = _env;
  context = _context;
  probeJson = CJsonObject("");
  if(safe_open == NULL)
  {
    get_safe_open();
  }
}

Probe::~Probe()
{
  if(context != NULL)
  { 
    env->DeleteLocalRef(context);
    context = NULL;
  }
}

void Probe::checkAll()
{

  clock_t start, finish; 
  double  duration;
  start = clock();

  checkRoot();
  checkSelinux();
  checkXposed();
  checkProxy();
  checkVpn();
  checkMulti();
  checkEmulator();
  checkPtrace();//ptrace检测需要再maps检测前面调用
  checkMaps();

  finish = clock();
  duration = (double)(finish - start) / CLOCKS_PER_SEC;
  LOGE("checkAll cost %f ms",duration);
}

string Probe::getProbeResult(){
  LOGD("StdSCO------鉴权开始------ ");
  clock_t start, finish; 
  start = clock();
  //if(auth_service("SysSafeCheck")){
    finish = clock();
    clock_t duration = (clock_t)(finish - start) / CLOCKS_PER_SEC;
    LOGD("StdSCO------鉴权完成 耗时： %d ms",duration);
    probeJson.ReplaceAdd("auth","success");
    checkAll();
//  }else{
//    probeJson.ReplaceAdd("auth","failed");
//  }
  probeJson.ReplaceAdd("nonce",createUUID(env));
  probeJson.ReplaceAdd("timestamp",getTimestamp());
  probeJson.ReplaceAdd("checksum",MD5(probeJson.ToString()).toString());
  return probeJson.ToString();
}

jstring getProbeRespStr(JNIEnv* env, jobject obj, jobject ctx)
{
  Probe *probe = new Probe(env,ctx);
  return env->NewStringUTF(probe->getProbeResult().c_str()); 
}

void Probe::report(const char* key, const char* value){
  CJsonObject json = probeJson;
  json.ReplaceAdd(key,value);
  json.ReplaceAdd("nonce",createUUID(env));
  json.ReplaceAdd("timestamp",getTimestamp());
  json.ReplaceAdd("checksum",MD5(json.ToString()).toString());
  LOGE("[+]Probe %s",json.ToString().c_str());
}

void Probe::report(){
  probeJson.ReplaceAdd("nonce",createUUID(env));
  probeJson.ReplaceAdd("timestamp",getTimestamp());
  probeJson.ReplaceAdd("checksum",MD5(probeJson.ToString()).toString());
  LOGE("[+]Probe %s",probeJson.ToString().c_str());
}


void Probe::findMemFrida(OINT base, OINT end, char* path) {
  if(!strstr(path,"/data/")){
    return;
  }
  //"frida:rpc"
  unsigned int len = 11;
  unsigned char buffer[] =
  {
    0xfe, 0xba, 0xfb, 0x4a, 0x9a, 0xca, 0x7f, 0xfb,
    0xdb, 0xea, 0xfe, 0xdc
  };

  for (unsigned char &m : buffer) {
      unsigned char c = m;
      c = ~c;
      c ^= 0xb1;
      c = (c >> 0x6) | (c << 0x2);
      c ^= 0x4a;
      c = (c >> 0x6) | (c << 0x2);
      m = c;
  }

  OINT rc = base;
  //LOGE("Probe findMemFrida:%lx %s",rc,path);
  while (rc < end-len ) {
    if (safe_memcmp((unsigned char *)rc, buffer, len) == 0) {
      probeJson["frida"]["detail"].Add(path);
      return;
    }
    rc += 1;
  }
}



void Probe::findMemHook(OINT base, OINT end,OINT offset, char* path){
#ifdef __LP64__
  unsigned int len = 8;
  unsigned char buffer[] =
  {
    0x1b, 0x4a, 0x4a, 0x12, 0x6a, 0x48, 0x55, 0x9c//0x51,0x00,0x00,0x58,0x20,0x02,0x1f,0xd6 //ldr x17,pc  bx x17
  };
  for (unsigned char &m : buffer) {
      unsigned char c = m;
      c ^= 0x4a;
      m = c;
  }
  OINT rc = base;
  //LOGE("Probe findMemHook:%lx %s",rc,path);
  while (rc < end-len ) {
    if (safe_memcmp((unsigned char *)rc, buffer, len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"%s+0x%x",path,rc-base+offset);
      probeJson["hook"]["detail"].Add(buffer);
      return;
    }
    rc += 1;
  }
  
#endif

#ifdef __arm__
  unsigned int len = 4;
  unsigned char buffer[] =
  {
    0x4e, 0xba, 0x55, 0xaf //04 f0 1f e5
  };
  for (unsigned char &m : buffer) {
      unsigned char c = m;
      c ^= 0x4a;
      m = c;
  }
  OINT rc = base;
  //LOGE("Probe findMemHook:%lx %s",rc,path);
  while (rc < end-len ) {
    if (memcmp((unsigned char *)rc, buffer, len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"%s+0x%x",path,rc-base+offset);
      probeJson["hook"]["detail"].Add(buffer);
      return;
    }
    rc += 1;
  }
#endif
  
}

void Probe::findMemBreakpoint(OINT base, OINT end, OINT offset, char* path){
#ifdef __arm__
  unsigned int arm_len = 4;
  unsigned char arm_buffer[] =
  {
    0xf1,0xf8,0x01,0xa1//0xf0, 0xf7, 0x00, 0xa0 
  };
  for (unsigned char &m : arm_buffer) {
      unsigned char c = m;
      c -= 0x1;
      m = c;
  }
  //printAddr((char*)arm_buffer);

  /*unsigned int thumb_len = 2;
  unsigned char thumb_buffer[] =
  {
    0x11, 0xdf //0x10,0xde
  };
  for (unsigned char &m : thumb_buffer) {
      unsigned char c = m;
      c -= 0x1;
      m = c;
  }*/
  //printAddr((char*)thumb_buffer);

  OINT rc = base;
  while (rc < end-8 ) {
    if (memcmp((unsigned char *)rc, arm_buffer, arm_len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"arm:%s+0x%x",path,rc-base+offset);
      probeJson["breakpoint"]["detail"].Add(buffer);
      return;
    }
    /*if (memcmp((unsigned char *)rc, thumb_buffer, thumb_len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"thumb:%s+0x%x",path,rc-base+offset);
      probeJson["breakpoint"].Add(buffer);
      return;
    }*/
    rc += 1;
  }
#elif __LP64__
  if(strstr(path,"libart.so")){
    return;
  }
  unsigned int arm_len = 4;
  unsigned char arm_buffer[] =
  {
    0x01,0x01,0x21,0xD5//00 00 20 d4
  };
  for (unsigned char &m : arm_buffer) {
      unsigned char c = m;
      c -= 0x1;
      m = c;
  }
  OINT rc = base;
  while (rc < end-8 ) {
    if (memcmp((unsigned char *)rc, arm_buffer, arm_len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"arm64:%s+0x%x",path,rc-base+offset);
      probeJson["breakpoint"]["detail"].Add(buffer);
      return;
    }
    /*if (memcmp((unsigned char *)rc, thumb_buffer, thumb_len) == 0) {
      char buffer[256] = {0};
      snprintf(buffer, 256,"thumb:%s+0x%x",path,rc-base+offset);
      probeJson["breakpoint"].Add(buffer);
      return;
    }*/
    rc += 1;
  }

#endif
}

int probe_safe_open(const char* path)
{
  //对safe_open包装一层 防止少数机型出现bug
  int fd = -1;
  fd = safe_open(0xFFFFFF9C,path,O_RDONLY|0x20000);
  return fd;
}

#define BUFFER_LEN 512
void Probe::checkMaps(){
  LOGD("checkMaps");
  int fd = -1;
  char path[256];
  char perm[5];
  unsigned long offset;
  OINT base=0;
  OINT end=0;
  char buffer[BUFFER_LEN];
  
  probeJson.AddEmptySubObject("frida");
  probeJson.AddEmptySubObject("hook");
  probeJson.AddEmptySubObject("breakpoint");
  probeJson["frida"].Add("result","false");
  probeJson["frida"].AddEmptySubArray("detail");
  probeJson["hook"].Add("result","false");
  probeJson["hook"].AddEmptySubArray("detail");
  probeJson["breakpoint"].Add("result","false");
  probeJson["breakpoint"].AddEmptySubArray("detail");

  if(safe_switch == 1){
    fd = open("/proc/self/maps", O_RDONLY);
  }else{
    fd = probe_safe_open("/proc/self/maps");
  }
  
  if (fd > 0) {
    while ((read_line(fd, buffer, BUFFER_LEN)) > 0) {
      if (sscanf(buffer, "%lx-%lx %4s %lx %*s %*s %s", &base, &end, perm, &offset, path) !=
          5) {
          continue;
      }
      if(strstr(buffer,"/dev/")){ // /dev/hw..这个内存会导致BUS_ADRERR
          continue;
      }
      if (perm[0] != 'r') continue;
      if (strlen(path) == 0) continue;
      //if (end - base <= 1000000) continue;
      if (!safe_endsWith(path, ".so")) continue;
      //LOGE("[+]Probe buffer:%s",buffer);
      //LOGE("[+]Probe base:%lx end:%lx path:%s",base,end,path);
      if(elf_check_header(base) == 1){
        findMemFrida(base,end,path);
      }
      if (perm[2] != 'x') continue;
      if (perm[3] != 'p') continue; //do not touch the shared memory
      findMemHook(base,end,offset,path);
      if(probeJson["ptrace"]["detail"].GetArraySize() > 0){
        findMemBreakpoint(base,end,offset,path);
      }
    }
    close(fd);
  }

  if(probeJson["frida"]["detail"].GetArraySize() > 0){
    probeJson["frida"].ReplaceAdd("result","true");
  }
  if(probeJson["hook"]["detail"].GetArraySize() > 0){
    probeJson["hook"].ReplaceAdd("result","true");
  }
  if(probeJson["breakpoint"]["detail"].GetArraySize() > 0){
    probeJson["breakpoint"].ReplaceAdd("result","true");
  }
  
}

void Probe::checkPtrace(){
  LOGD("checkPtrace");
  probeJson.AddEmptySubObject("ptrace");
  int fd = -1;
  if(safe_switch == 1){
    fd = open("/proc/self/status",O_RDONLY);
  }else{
    fd = probe_safe_open("/proc/self/status");
  }
  if(fd>0){
    char buffer[BUFFER_LEN];
    while ((read_line(fd, buffer, BUFFER_LEN)) > 0) {
      if(strstr(buffer,"TracerPid")){
        int pid = 0;
        char tmp[32];
        sscanf(buffer, "%s  %d",tmp,&pid);
        if(pid>0){
          probeJson["ptrace"].Add("result","true");
          probeJson["ptrace"].AddEmptySubArray("detail");
          char cmdline[32] = {0};
          sprintf(cmdline,"/proc/%d/cmdline",pid);
          char name[64] = {0};
          int ret = read_file(cmdline,name,64);
          if(ret){
            probeJson["ptrace"]["detail"].Add(name);
          }else{
            probeJson["ptrace"]["detail"].Add(pid);
          }
          close(fd);
          return;
        }
        break;
      }
    }
    close(fd);
  }
  probeJson["ptrace"].Add("result","false");
}



void Probe::checkRoot(){
  LOGD("checkRoot");
  probeJson.AddEmptySubObject("root");
  vector<string> path_arr = {"/system/bin/su", "/system/xbin/su", "/system/sbin/su", "/vendor/bin/su"};
  int flag = 0;
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      flag = 1;
      probeJson["root"].Add("result","true");
      probeJson["root"].AddEmptySubArray("detail");
      probeJson["root"]["detail"].Add(path);
      break;
    }
  }
  if(flag==0)
  {
    probeJson["root"].Add("result","false");
  }

}

void Probe::checkSelinux(){
  LOGD("checkSelinux");
  probeJson.AddEmptySubObject("selinux");
  char result[128]="";                   
  if(1==exe_cmd("getenforce",result)){
    if(strstr(result,"Permissive") || strstr(result,"Disabled")){
      probeJson["selinux"].Add("result","true");
      probeJson["selinux"].AddEmptySubArray("detail");
      probeJson["selinux"]["detail"].Add(result);
      return;
    }
  }
  probeJson["selinux"].Add("result","false");
}

void Probe::checkXposed(){
  LOGD("checkXposed");
  probeJson.AddEmptySubObject("xposed");
  jclass jclazz = env->FindClass("de/robv/android/xposed/XposedBridge");//com.swift.sandhook.xposedcompat.hookstub.HookStubManager
  JniExceptionCheck();
  if(jclazz!=NULL){
    probeJson["xposed"].Add("result","true");
    env->DeleteLocalRef(jclazz);
    return;
  }
  vector<string> path_arr = {"/data/data/com.topjohnwu.magisk", "/data/data/org.meowcat.edxposed.manager","/data/data/io.va.exposed"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["xposed"].Add("result","true");
      return;
    }
  }
  probeJson["xposed"].Add("result","false");
}

vector<string> split(const char *s, const char *delim)
{
    vector<string> result;
    if (s && strlen(s))
    {
        int len = strlen(s);
        char *src = new char[len + 1];
        strcpy(src, s);
        src[len] = '\0';
        char *tokenptr = strtok(src, delim);
        while (tokenptr != NULL)
        {
            string tk = tokenptr;
            result.emplace_back(tk);
            tokenptr = strtok(NULL, delim);
        }
        delete[] src;
    }
    return result;
}

void Probe::checkMulti(){
  LOGD("checkMulti");
  probeJson.AddEmptySubObject("separation");
  do{
    jclass jclazz = env->FindClass("android/content/ContextWrapper");
    jmethodID mid = env->GetMethodID(jclazz,"getFilesDir","()Ljava/io/File;");
    jobject jfile = env->CallObjectMethod(context,mid);

    env->DeleteLocalRef(jclazz);
    jclazz = NULL;
    jclazz = env->FindClass("java/io/File");
    mid = env->GetMethodID(jclazz,"getAbsolutePath","()Ljava/lang/String;");
    jstring jstr = (jstring)env->CallObjectMethod(jfile,mid);
    env->DeleteLocalRef(jclazz);

    char *str = (char *)env->GetStringUTFChars(jstr, NULL);
    string absolutePath(str);
    env->ReleaseStringUTFChars(jstr, str);
    env->DeleteLocalRef(jstr);
    env->DeleteLocalRef(jfile);

    string packageName = getPackageName(env,context);
    vector<string> v_str = split(absolutePath.c_str(),"/");
    for(string str: v_str){
      if(str.find(".") != string::npos){
        if(str != packageName){
          LOGE("absolutePath:%s",absolutePath.c_str());
          probeJson["separation"].Add("result","true");
          probeJson["separation"].AddEmptySubArray("detail");
          probeJson["separation"]["detail"].Add(str);
          return;
        }
      }
    }
    ///data/user/0/info.red.virtual/virtual/data/user/0/com.opos.mobaddemo/files
    ///data/user/0/com.excean.maid/gameplugins/com.opos.mobaddemo/files
  }while(false);
  probeJson["separation"].Add("result","false");
}


void Probe::checkProxy(){
  LOGD("checkProxy");
  probeJson.AddEmptySubObject("proxy");
  jclass System = env->FindClass("java/lang/System");
  jmethodID System_getProperty = env->GetStaticMethodID(System, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
  jstring jstr_host = env->NewStringUTF("http.proxyHost");
  jstring jstr_host_value = (jstring)(env->CallStaticObjectMethod(System, System_getProperty, jstr_host));
  if(jstr_host_value!=NULL){
    char *str_ret = (char *)env->GetStringUTFChars(jstr_host_value, NULL);
    probeJson["proxy"].Add("result","true");
    probeJson["proxy"].AddEmptySubArray("detail");
    probeJson["proxy"]["detail"].Add(str_ret);
    env->ReleaseStringUTFChars(jstr_host_value, str_ret);
    env->DeleteLocalRef(jstr_host_value);
  }else{
    probeJson["proxy"].Add("result","false");
  }
  env->DeleteLocalRef(System);
  env->DeleteLocalRef(jstr_host);
}

//@RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
void Probe::checkVpn()
{
  LOGD("checkVpn");
  jclass jclazz = NULL;
  jobject jmg = NULL;
  jobject jnwinfo = NULL;
  jobject jnwcab = NULL;
  do{
    jclazz = env->FindClass("android/app/Application");
    jmethodID mid = env->GetMethodID(jclazz,"getSystemService","(Ljava/lang/String;)Ljava/lang/Object;");
    jstring jstr = env->NewStringUTF("connectivity");
    jmg = env->CallObjectMethod(context,mid,jstr);
    env->DeleteLocalRef(jstr);
    jstr = NULL;
    env->DeleteLocalRef(jclazz);
    jclazz = NULL;
    jclazz = env->FindClass("android/net/ConnectivityManager");
    JniExceptionCheck();
    if(jclazz==NULL){
      LOGD("[-]checkVpn jclazz==NULL");
      break;
    }
    mid = env->GetMethodID(jclazz,"getActiveNetwork","()Landroid/net/Network;");
    JniExceptionCheck();
    if(mid == NULL){
      LOGD("[-]checkVpn getActiveNetwork==NULL");
      break;
    }
    jnwinfo = env->CallObjectMethod(jmg,mid);
    JniExceptionCheck();
    if(jnwinfo==NULL){
      LOGD("[-]checkVpn jnwinfo==NULL");
      break;
    }
    mid = env->GetMethodID(jclazz,"getNetworkCapabilities","(Landroid/net/Network;)Landroid/net/NetworkCapabilities;");
    JniExceptionCheck();
    if(mid == NULL){
      LOGD("[-]checkVpn getNetworkCapabilities==NULL");
      break;
    }
    jnwcab = env->CallObjectMethod(jmg,mid,jnwinfo);
    JniExceptionCheck();
    if(jnwcab==NULL){
      LOGD("[-]checkVpn jnwcab==NULL");
      break;
    }
    env->DeleteLocalRef(jclazz);
    jclazz = env->FindClass("android/net/NetworkCapabilities");
    mid = env->GetMethodID(jclazz, "toString", "()Ljava/lang/String;");
    jstr = (jstring)env->CallObjectMethod(jnwcab,mid);
    char *str = (char *)env->GetStringUTFChars(jstr, NULL);
    string NetworkCapabilities(str);
    LOGD("VPN:%s",str);
    probeJson.AddEmptySubObject("vpn");
    probeJson["vpn"].Add("result","false");
    if(NetworkCapabilities.find("Transports:") != string::npos){
      if(NetworkCapabilities.find("NOT_VPN") != string::npos){
        probeJson["vpn"].ReplaceAdd("result","false");
      }else{
        probeJson["vpn"].ReplaceAdd("result","true");
      }
    }
    //NOT_METERED&INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED&NOT_ROAMING&FOREGROUND&NOT_CONGESTED&NOT_SUSPENDED
    //INTERNET&NOT_RESTRICTED&TRUSTED&VALIDATED&NOT_ROAMING&FOREGROUND&NOT_CONGESTED&NOT_SUSPENDED 

    env->ReleaseStringUTFChars(jstr, str);
    env->DeleteLocalRef(jstr);
    
  }while(false);
  
  if(jclazz)
    env->DeleteLocalRef(jclazz);
  if(jmg)
    env->DeleteLocalRef(jmg);
  if(jnwinfo)
    env->DeleteLocalRef(jnwinfo);
  if(jnwcab)
    env->DeleteLocalRef(jnwcab);
}


void Probe::checkEmulator()
{
  LOGD("checkEmulator");
  probeJson.AddEmptySubObject("emulator");
  vector<string> path_arr = {"/system/lib/egl/libEGL_tencent.so", "/system/lib/egl/libGLESv2_tencent.so","/system/lib64/egl/libEGL_tencent.so","/system/lib64/egl/libGLESv2_tencent.so"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("tencent");
      return;
    }
  }

  path_arr = {"/system/bin/droid4x", "/system/bin/droid4x-prop","/system/bin/droid4x-vbox-sf","/system/bin/droid4x_setprop"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("droid4x");
      return;
    }
  }

  path_arr = {"/data/data/com.android.flysilkworm", "/ueventd.android_x86.rc","/init.android_x86.rc","/fstab.android_x86"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("ldmnq");
      return;
    }
  }

  path_arr = {"/data/data/com.bignox.app.store.hd", "/system/bin/nox-prop","/system/bin/nox-vbox-sf","/system/bin/noxd","/system/lib/libnoxd.so","/system/app/Helper/NoxHelp_zh.apk"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("yeshen");
      return;
    }
  }

  path_arr = {"/system/etc/mumu-configs/device-prop-configs/mumu.config", "/data/data/com.mumu.store"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("mumu");
      return;
    }
  }

  path_arr = {"/system/bin/ludashi-prop", "/system/etc/init.ludashi.sh"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("ludashi");
      return;
    }
  }

  path_arr = {"/data/data/com.microvirt.market"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("xiaoyao");
      return;
    }
  }

  path_arr = {"/system/etc/init.tiantian.sh", "/system/lib/egl/libEGL_tiantianVM.so","/system/lib/egl/libGLESv1_CM_tiantianVM.so","/system/lib/egl/libGLESv2_tiantianVM.so"};
  for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    if(file_exists(path.c_str())){
      probeJson["emulator"].Add("result","true");
      probeJson["emulator"].AddEmptySubArray("detail");
      probeJson["emulator"]["detail"].Add("tiantian");
      return;
    }
  }
  //TODO:解析/proc/cpuinfo，检测芯片是否intel、amd，固件信息是否包含Genymotion、Emulator、generic_x86

  probeJson["emulator"].Add("result","false");
}

#include <sys/mman.h>
void get_safe_open()
{

   void *handle = dlopen("libc.so",0);
   safe_openat = (int (*)(int,const char *, int))dlsym(handle,"__openat");

   char *ptr = (char*)mmap(NULL, 4096, PROT_READ|PROT_WRITE |PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#ifdef __arm__
   int len = sizeof(openatBuf);
   LOGE("get_safe_open arm");
   memcpy(ptr,openatBuf,len);
   for(int i=0;i<len;i++){
      if(ptr[i] != 0xFF){
        ptr[i] -= 0x1;
      }
   }
#elif __LP64__
   LOGE("get_safe_open arm64");
   int len = sizeof(openatBuf64);
   memcpy(ptr,openatBuf64,len);
   for(int i=0;i<len;i++){
      if(ptr[i] != 0xFF){
        ptr[i] -= 0x1;
      }
   }
#else
   LOGE("get_safe_open other");
   //ptr = (char*)safe_openat;
   safe_switch = 1;
#endif

   safe_open = (int (*)(int,const char *, int))ptr;
   if(safe_openat == NULL){
    LOGD("dlsym __openat failed");
    safe_openat = safe_open;
   }

   vector<string> path_arr = {"/data/data/com.mumu.store", "/system/bin/droid4x"};
   for(int i=0;i<path_arr.size();i++){
    string path = path_arr[i];
    int fd = open(path.c_str(),O_RDONLY);
    if(fd>0){
      LOGD("safe_switch for:%s",path.c_str());
      close(fd);
      safe_switch = 1;
      return;
    }else{
      if(errno == 13){
        LOGD("open %s failed! errno:%d",path.c_str(),errno);
        safe_switch = 1;
      }
    }
  }
   
}

bool file_exists(const char *path)
{
  int fd = -1;
  if(safe_switch == 1){
    LOGD("open:%s",path);
    fd = open(path,O_RDONLY);
  }else{
    LOGD("safe_openat:%s",path);
    fd = safe_openat(0xFFFFFF9C,path,O_RDONLY|0x20000);
  }
  if(fd>0){
    close(fd);
    return true;
  }else{
    if(errno == 13){
      LOGD("open %s failed! errno:%d",path,errno);
      return true;
    }
  }
  return false;
}

