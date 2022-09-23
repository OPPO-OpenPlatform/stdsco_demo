#include <jni.h>
#include <android/log.h>
#include <sys/time.h>
#include <stdio.h>
#include <pthread.h>
#include <mutex>
#include <map>

#include "curl/curl.h"
#include "auth.h"
#include "md5.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#if __USE_ONEWAY_CERTIFICATION__
#include "auth_ca.h"
#endif

#if 0
#define LOGD(format, ...) __android_log_print(ANDROID_LOG_DEBUG, "sco_auth", format "\t\t[Func:%s][Line:%d]", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#else
#define LOGD(...) while(0){;}
#endif

extern JavaVM *g_jvm;

char *g_appId_c = NULL;
char *g_oppoSign_c = NULL;

static std::string gPackageName = "";

std::mutex _threadMutex;
std::map<std::string, bool> gAuthMap;

uint64 getCurrTimestamp(){
    struct timeval current;
    gettimeofday(&current, NULL);
    uint64 currentTime = (uint64)current.tv_sec * 1000 + (uint64)current.tv_usec / 1000;
    return currentTime;
}

std::string getPackageName()
{
    if(gPackageName.length() > 0){
        return gPackageName;
    }

    FILE *fp;
    char line[512];
    unsigned int pos;
    if(NULL == (fp = fopen("/proc/self/cmdline", "r")))
    {
        LOGD("fopen /proc/self/cmdline failed");
        return gPackageName;
    }
    fgets(line, sizeof(line), fp);
    LOGD("line:[%s]", line);
    sscanf(line, "%*s%n", &pos);
    gPackageName = std::string(line, 0, pos);
    return gPackageName;
}

static bool JniExceptionCheck(JNIEnv *env)
{
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
        return true;
    }
    return false;
}

static void generateOppoSign(JNIEnv *env, jclass clz, jobject context_object){
    //不重复生成
    if(g_oppoSign_c)
        return;

    jclass context_class = env->GetObjectClass(context_object);

    //context.getPackageManager()
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager_object = env->CallObjectMethod(context_object, methodId);
    if (package_manager_object == NULL) {
        LOGD("getPackageManager() Failed!");
        return;
    }
    env->DeleteLocalRef(context_class);

    //context.getPackageName()
    std::string pack_name = getPackageName();
    jstring package_name_string = env->NewStringUTF(pack_name.c_str());

    //PackageManager.getPackageInfo(Sting, int)
    //public static final int GET_SIGNATURES= 0x00000040;
    jclass pack_manager_class = env->GetObjectClass(package_manager_object);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info_object = env->CallObjectMethod(package_manager_object, methodId, package_name_string, 0x40);
    if (package_info_object == NULL) {
        LOGD("getPackageInfo() Failed!");
        return;
    }
    env->DeleteLocalRef(package_manager_object);

    //rawSignature = PackageInfo.signatures
    jclass package_info_class = env->GetObjectClass(package_info_object);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray)env->GetObjectField(package_info_object, fieldId);
    env->DeleteLocalRef(package_info_object);
    if (signature_object_array == NULL) {
        LOGD("PackageInfo.signatures[] is null");
        return;
    }

    //ArrayList arrayList = new ArrayList();
    jclass array_list_class = env->FindClass("java/util/ArrayList");
    methodId = env->GetMethodID(array_list_class, "<init>", "()V");
    jobject array_list_object = env->NewObject(array_list_class, methodId);

    //for (Signature signature : rawSignature)
    int array_len = env->GetArrayLength(signature_object_array);
    for(int i = 0; i < array_len; i++) {
        jobject signature_object = env->GetObjectArrayElement(signature_object_array, i);

        //Signature.toByteArray()
        jclass signature_class = env->GetObjectClass(signature_object);
        methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
        env->DeleteLocalRef(signature_class);
        jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);

        //new ByteArrayInputStream
        jclass byte_array_input_class=env->FindClass("java/io/ByteArrayInputStream");
        methodId=env->GetMethodID(byte_array_input_class,"<init>","([B)V");
        jobject byte_array_input=env->NewObject(byte_array_input_class,methodId,signature_byte);

        //CertificateFactory.getInstance("X.509")
        jclass certificate_factory_class=env->FindClass("java/security/cert/CertificateFactory");
        methodId=env->GetStaticMethodID(certificate_factory_class,"getInstance","(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
        jstring x_509_jstring=env->NewStringUTF("X.509");
        jobject cert_factory=env->CallStaticObjectMethod(certificate_factory_class,methodId,x_509_jstring);

        //certFactory.generateCertificate(byteIn);
        methodId=env->GetMethodID(certificate_factory_class,"generateCertificate",("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
        jobject x509_cert=env->CallObjectMethod(cert_factory,methodId,byte_array_input);
        env->DeleteLocalRef(certificate_factory_class);

        //cert.getEncoded()
        jclass x509_cert_class=env->GetObjectClass(x509_cert);
        methodId=env->GetMethodID(x509_cert_class,"getEncoded","()[B");
        jbyteArray cert_byte=(jbyteArray)env->CallObjectMethod(x509_cert,methodId);
        env->DeleteLocalRef(x509_cert_class);

        //byteToHexString
        const char HexCode[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        jsize cert_size = env->GetArrayLength(cert_byte);
        jbyte* cert = env->GetByteArrayElements(cert_byte,NULL);
        char* hex_cert = (char*)malloc(cert_size*2 + 1);
        memset(hex_cert, 0, cert_size*2 + 1);
        for (int i = 0; i < cert_size ; ++i) {
            hex_cert[2*i]=HexCode[((unsigned char)cert[i])/16];
            hex_cert[2*i+1]=HexCode[((unsigned char)cert[i])%16];
        }
        hex_cert[cert_size*2]='\0';
        env->ReleaseByteArrayElements(cert_byte, cert, NULL);
        jstring cert_hex_string = env->NewStringUTF(hex_cert);

        //str.getBytes()
        jclass string_class=env->FindClass("java/lang/String");
        methodId=env->GetMethodID(string_class, "getBytes", "()[B");
        jbyteArray cert_hex_byte = (jbyteArray)env->CallObjectMethod(cert_hex_string, methodId);

        //MessageDigest.getInstance("MD5")
        jclass message_digest_class=env->FindClass("java/security/MessageDigest");
        methodId=env->GetStaticMethodID(message_digest_class,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
        jstring md5_jstring=env->NewStringUTF("MD5");
        jobject md5_digest=env->CallStaticObjectMethod(message_digest_class,methodId,md5_jstring);

        //digest.update(str.getBytes());
        methodId=env->GetMethodID(message_digest_class,"update","([B)V");
        env->CallVoidMethod(md5_digest,methodId,cert_hex_byte);

        //digest.digest()
        methodId=env->GetMethodID(message_digest_class,"digest","()[B");
        jbyteArray md5_byte = (jbyteArray)env->CallObjectMethod(md5_digest,methodId);
        env->DeleteLocalRef(message_digest_class);

        //new BigInteger(1, bArr)
        jclass big_integer_class=env->FindClass("java/math/BigInteger");
        methodId=env->GetMethodID(big_integer_class, "<init>", "(I[B)V");
        jobject big_integer = env->NewObject(big_integer_class, methodId, 1, md5_byte);
        env->DeleteLocalRef(big_integer_class);

        //String.format("%032x", big_integer);
        jclass object_class = env->FindClass("java/lang/Object");
        jobjectArray object_array = env->NewObjectArray(1, object_class, NULL);
        env->SetObjectArrayElement(object_array, 0, big_integer);
        env->DeleteLocalRef(object_class);
        methodId = env->GetStaticMethodID(string_class, "format", "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;");
        jstring fmt_jstring=env->NewStringUTF("%032x");
        jstring hex_string = (jstring)env->CallStaticObjectMethod(string_class, methodId, fmt_jstring, object_array);
        env->DeleteLocalRef(string_class);

        //arrayList.contains(hex_string)
        methodId = env->GetMethodID(array_list_class, "contains", "(Ljava/lang/Object;)Z");
        jboolean isContain = env->CallBooleanMethod(array_list_object, methodId, hex_string);
        if(isContain == JNI_FALSE) {
            methodId = env->GetMethodID(array_list_class, "add", "(Ljava/lang/Object;)Z");
            env->CallBooleanMethod(array_list_object, methodId, hex_string);
        }

        //byteArrayInputStream.close()
        methodId = env->GetMethodID(byte_array_input_class, "close", "()V");
        env->CallVoidMethod(byte_array_input, methodId);
        env->DeleteLocalRef(byte_array_input_class);
    }

    //Collections.sort(arrayList)
    jclass collection_class = env->FindClass("java/util/Collections");
    methodId = env->GetStaticMethodID(collection_class, "sort", "(Ljava/util/List;)V");
    env->CallStaticVoidMethod(collection_class, methodId, array_list_object);
    env->DeleteLocalRef(collection_class);

    //StringBuilder sb = new StringBuilder();
    jclass string_builder_class = env->FindClass("java/lang/StringBuilder");
    methodId = env->GetMethodID(string_builder_class, "<init>", "()V");
    jobject string_builder_object = env->NewObject(string_builder_class, methodId);

    //arrayList.toArray()
    methodId = env->GetMethodID(array_list_class, "toArray", "()[Ljava/lang/Object;");
    jobjectArray string_array = (jobjectArray)env->CallObjectMethod(array_list_object, methodId);

    //sb.append(str)
    //sb.append(",")
    int string_array_len = env->GetArrayLength(string_array);
    jstring separator_jstring=env->NewStringUTF(",");
    for(int i = 0; i < string_array_len; i++){
        jstring string = (jstring)env->GetObjectArrayElement(string_array, i);
        methodId = env->GetMethodID(string_builder_class, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
        string_builder_object = env->CallObjectMethod(string_builder_object, methodId, string);
        string_builder_object = env->CallObjectMethod(string_builder_object, methodId, separator_jstring);
    }

    //sb.toString()
    methodId = env->GetMethodID(string_builder_class, "toString", "()Ljava/lang/String;");
    jobject to_string = env->CallObjectMethod(string_builder_object, methodId);

    //to_string.substring(0, 32)
    jclass string_class=env->FindClass("java/lang/String");
    methodId = env->GetMethodID(string_class, "length", "()I");
    int string_len = env->CallIntMethod(to_string, methodId);
    int length = (string_len - 1 > 32) ? 32 : (string_len - 1);
    methodId = env->GetMethodID(string_class, "substring", "(II)Ljava/lang/String;");
    to_string = env->CallObjectMethod(to_string, methodId, 0, length);

    //g_oppoSign_c
    const char *oppoSign_c = env->GetStringUTFChars((jstring)to_string, NULL);
    g_oppoSign_c = (char*)malloc(length + 1);
    memset(g_oppoSign_c, 0, length + 1);
    memcpy(g_oppoSign_c, oppoSign_c, length);
    env->ReleaseStringUTFChars((jstring)to_string, oppoSign_c);

    env->DeleteLocalRef(string_class);
    env->DeleteLocalRef(string_builder_class);
    env->DeleteLocalRef(array_list_class);

    LOGD("g_oppoSign_c:%s", g_oppoSign_c);
}

#if __USE_JNI_ENCRYPT__
std::string generateRandomAESKey(){
    JNIEnv *env = NULL;
    bool detached = g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (detached)
        g_jvm->AttachCurrentThread(&env, NULL);

    //KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    jclass key_generator_class = env->FindClass("javax/crypto/KeyGenerator");
    jmethodID methodId = env->GetStaticMethodID(key_generator_class, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;");
    jstring aes_string = env->NewStringUTF("AES");
    jobject key_generator_object = env->CallStaticObjectMethod(key_generator_class, methodId, aes_string);

    //keyGenerator.init(128);
    methodId = env->GetMethodID(key_generator_class, "init", "(I)V");
    env->CallVoidMethod(key_generator_object, methodId, 256);

    //SecretKey secretKey = keyGenerator.generateKey();
    methodId = env->GetMethodID(key_generator_class, "generateKey", "()Ljavax/crypto/SecretKey;");
    jobject secretKey_object = env->CallObjectMethod(key_generator_object, methodId);

    //secretKey.getEncoded()
    jclass secretkey_class = env->FindClass("javax/crypto/SecretKey");
    methodId = env->GetMethodID(secretkey_class, "getEncoded", "()[B");
    jbyteArray key_byte=(jbyteArray)env->CallObjectMethod(secretKey_object, methodId);

    jsize key_size = env->GetArrayLength(key_byte);
    jbyte* key = env->GetByteArrayElements(key_byte,NULL);
    std::string aes_key((const char*)key, key_size);

    env->ReleaseByteArrayElements(key_byte, key, NULL);
    env->DeleteLocalRef(key_generator_class);
    env->DeleteLocalRef(secretkey_class);
    if (detached)
        g_jvm->DetachCurrentThread();
    return aes_key;
}

std::string encryptDataWithAES(std::string& aesKey, std::string& dataStr){
    JNIEnv *env = NULL;
    bool detached = g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (detached)
        g_jvm->AttachCurrentThread(&env, NULL);

    jsize key_size = aesKey.length();
    jbyte* key = (jbyte*)aesKey.c_str();
    jbyteArray key_byte = env->NewByteArray(key_size);
    env->SetByteArrayRegion(key_byte,0, key_size, key);

    jsize data_size = dataStr.length();
    jbyte* data = (jbyte*)dataStr.c_str();
    jbyteArray data_byte = env->NewByteArray(data_size);
    env->SetByteArrayRegion(data_byte,0, data_size, data);

    //SecretKeySpec skeySpec = new SecretKeySpec(byteArray, "AES");
    jclass secret_class = env->FindClass("javax/crypto/spec/SecretKeySpec");
    jmethodID methodId=env->GetMethodID(secret_class, "<init>", "([BLjava/lang/String;)V");
    jstring aes_string = env->NewStringUTF("AES");
    jobject secret_object = env->NewObject(secret_class, methodId, key_byte, aes_string);

    //Cipher cipher = Cipher.getInstance("AES");
    jclass cipher_class = env->FindClass("javax/crypto/Cipher");
    methodId = env->GetStaticMethodID(cipher_class, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jstring aes_mode_string = env->NewStringUTF("AES/ECB/PKCS5Padding");
    jobject cipher_object = env->CallStaticObjectMethod(cipher_class, methodId, aes_mode_string);

    //cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
    methodId = env->GetMethodID(cipher_class, "init", "(ILjava/security/Key;)V");
    env->CallVoidMethod(cipher_object, methodId, 1, secret_object);

    //cipher.doFinal(bytIn);
    methodId = env->GetMethodID(cipher_class, "doFinal", "([B)[B");
    jbyteArray final_array = (jbyteArray)env->CallObjectMethod(cipher_object, methodId, data_byte);

    jsize final_size = env->GetArrayLength(final_array);
    jbyte* final = env->GetByteArrayElements(final_array,NULL);
    std::string final_str((const char*)final, final_size);

    env->ReleaseByteArrayElements(final_array, final, NULL);
    env->DeleteLocalRef(secret_class);
    env->DeleteLocalRef(cipher_class);
    env->DeleteLocalRef(key_byte);
    env->DeleteLocalRef(data_byte);
    if (detached)
        g_jvm->DetachCurrentThread();
    return final_str;
}

std::string descryptDataWithAES(std::string& aesKey, std::string& dataStr){
    JNIEnv *env = NULL;
    bool detached = g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (detached)
        g_jvm->AttachCurrentThread(&env, NULL);

    jsize key_size = aesKey.length();
    jbyte* key = (jbyte*)aesKey.c_str();
    jbyteArray key_byte = env->NewByteArray(key_size);
    env->SetByteArrayRegion(key_byte,0, key_size, key);

    jsize data_size = dataStr.length();
    jbyte* data = (jbyte*)dataStr.c_str();
    jbyteArray data_byte = env->NewByteArray(data_size);
    env->SetByteArrayRegion(data_byte,0, data_size, data);

    //SecretKeySpec skeySpec = new SecretKeySpec(byteArray, "AES");
    jclass secret_class = env->FindClass("javax/crypto/spec/SecretKeySpec");
    jmethodID methodId=env->GetMethodID(secret_class, "<init>", "([BLjava/lang/String;)V");
    jstring aes_string = env->NewStringUTF("AES");
    jobject secret_object = env->NewObject(secret_class, methodId, key_byte, aes_string);

    //Cipher cipher = Cipher.getInstance("AES");
    jclass cipher_class = env->FindClass("javax/crypto/Cipher");
    methodId = env->GetStaticMethodID(cipher_class, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jstring aes_mode_string = env->NewStringUTF("AES/ECB/PKCS5Padding");
    jobject cipher_object = env->CallStaticObjectMethod(cipher_class, methodId, aes_mode_string);

    //cipher.init(Cipher.DECRYPT_MODE, skeySpec);
    methodId = env->GetMethodID(cipher_class, "init", "(ILjava/security/Key;)V");
    env->CallVoidMethod(cipher_object, methodId, 2, secret_object);

    //cipher.doFinal(bytIn);
    methodId = env->GetMethodID(cipher_class, "doFinal", "([B)[B");
    jbyteArray final_array = (jbyteArray)env->CallObjectMethod(cipher_object, methodId, data_byte);
    JniExceptionCheck(env);

    std::string final_str = "";
    if(final_array != NULL) {
        jsize final_size = env->GetArrayLength(final_array);
        jbyte *final = env->GetByteArrayElements(final_array, NULL);
        final_str = std::string((const char *) final, final_size);
        env->ReleaseByteArrayElements(final_array, final, NULL);
    } else {
        final_str = dataStr;
        LOGD("descryptDataWithAES failed!");
    }

    env->DeleteLocalRef(secret_class);
    env->DeleteLocalRef(cipher_class);
    env->DeleteLocalRef(key_byte);
    env->DeleteLocalRef(data_byte);
    if (detached)
        g_jvm->DetachCurrentThread();
    return final_str;
}

std::string encryptDataWithPubKey(std::string& dataStr){
    unsigned char pubKey[] = {
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xcd, 0x8c, 0xed, 0x23, 0xba, 0x3d, 0x94, 0x76, 0xf7, 0x1c, 0x7c, 0x11, 0x4e, 0xc8, 0x1a,
        0xb5, 0x46, 0xc9, 0xb2, 0x05, 0x13, 0x88, 0x67, 0x5f, 0x23, 0x08, 0xde, 0x16, 0x3e, 0x28, 0x0e,
        0xbf, 0xc3, 0x37, 0xf6, 0x2c, 0x10, 0xde, 0xc2, 0x58, 0x71, 0xa4, 0xb7, 0x4c, 0x99, 0x14, 0xa1,
        0x48, 0x28, 0xcc, 0x3e, 0x86, 0x17, 0xfa, 0x54, 0x18, 0xd0, 0x4a, 0xa5, 0x3d, 0xa4, 0x17, 0xc1,
        0x86, 0x10, 0x88, 0x50, 0xc1, 0xdd, 0x59, 0xbc, 0xcf, 0x0f, 0x85, 0x34, 0x02, 0x0b, 0x54, 0xaf,
        0x91, 0x79, 0xf8, 0x36, 0x3c, 0xa8, 0xe4, 0x74, 0x5e, 0x60, 0xc6, 0x0a, 0x23, 0x47, 0xb7, 0xef,
        0x3f, 0xbb, 0x5b, 0xb3, 0x09, 0x75, 0x8b, 0xb3, 0x29, 0xb7, 0x7c, 0xc4, 0x0a, 0xf6, 0x41, 0x09,
        0x65, 0xde, 0x88, 0xd4, 0xc5, 0xc3, 0x56, 0x5b, 0xc6, 0xa1, 0x4d, 0x64, 0x8e, 0x06, 0x5f, 0x5b,
        0xe0, 0x9f, 0x51, 0xbb, 0xe2, 0xab, 0xb3, 0x1d, 0x5b, 0x05, 0x63, 0xc5, 0x93, 0xef, 0x4c, 0x3f,
        0xd0, 0xb6, 0xbb, 0x2a, 0x00, 0x2e, 0xbb, 0x68, 0xd1, 0xc6, 0x47, 0xda, 0x6c, 0xa7, 0xe4, 0x6d,
        0xdf, 0xaf, 0x0d, 0xbd, 0x20, 0x56, 0xfa, 0x9f, 0x74, 0xea, 0x36, 0x5e, 0x4e, 0x81, 0xee, 0x80,
        0x50, 0xa9, 0xa2, 0xab, 0xfc, 0x36, 0xa3, 0x86, 0x77, 0xd5, 0x89, 0xa7, 0x0f, 0x1f, 0xed, 0x6b,
        0x66, 0x5f, 0x61, 0x5a, 0xb7, 0xd3, 0x08, 0xf3, 0xba, 0x56, 0x15, 0x07, 0x2e, 0xa6, 0x31, 0x08,
        0xce, 0x45, 0x91, 0x57, 0x95, 0x41, 0xa3, 0xcb, 0xe1, 0x66, 0xb9, 0x70, 0x5c, 0x3e, 0x07, 0x75,
        0x96, 0x01, 0x1b, 0xa4, 0x80, 0x33, 0x6f, 0xdc, 0x0b, 0xb5, 0x9f, 0xb1, 0xce, 0x4b, 0xe5, 0x65,
        0xf6, 0x2b, 0xa1, 0xef, 0xb1, 0xa1, 0xb6, 0xc2, 0xd9, 0xd5, 0xc6, 0xc6, 0x1e, 0x9c, 0xf6, 0x65,
        0xdf, 0x02, 0x03, 0x01, 0x00, 0x01
    };

    JNIEnv *env = NULL;
    bool detached = g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (detached)
        g_jvm->AttachCurrentThread(&env, NULL);

    jsize key_size = sizeof (pubKey);
    jbyte* key = (jbyte*)pubKey;
    jbyteArray key_byte = env->NewByteArray(key_size);
    env->SetByteArrayRegion(key_byte,0, key_size, key);

    jsize data_size = dataStr.length();
    jbyte* data = (jbyte*)dataStr.c_str();
    jbyteArray data_byte = env->NewByteArray(data_size);
    env->SetByteArrayRegion(data_byte,0, data_size, data);

    //X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubArray);
    jclass secret_class = env->FindClass("java/security/spec/X509EncodedKeySpec");
    jmethodID methodId=env->GetMethodID(secret_class, "<init>", "([B)V");
    jobject secret_object = env->NewObject(secret_class, methodId, key_byte);

    //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    jclass key_factory_class = env->FindClass("java/security/KeyFactory");
    methodId = env->GetStaticMethodID(key_factory_class, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyFactory;");
    jstring rsa_string = env->NewStringUTF("RSA");
    jobject key_factory_object = env->CallStaticObjectMethod(key_factory_class, methodId, rsa_string);

    //publicKey = keyFactory.generatePublic(publicKeySpec);
    methodId = env->GetMethodID(key_factory_class, "generatePublic", "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;");
    jobject pubkey_object = env->CallObjectMethod(key_factory_object, methodId, secret_object);

    //Cipher cipher = Cipher.getInstance("RSA");
    jclass cipher_class = env->FindClass("javax/crypto/Cipher");
    methodId = env->GetStaticMethodID(cipher_class, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jstring rsa_mode_string = env->NewStringUTF("RSA/ECB/PKCS1Padding");
    jobject cipher_object = env->CallStaticObjectMethod(cipher_class, methodId, rsa_mode_string);

    //cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
    methodId = env->GetMethodID(cipher_class, "init", "(ILjava/security/Key;)V");
    env->CallVoidMethod(cipher_object, methodId, 1, pubkey_object);

    //cipher.doFinal(bytIn);
    methodId = env->GetMethodID(cipher_class, "doFinal", "([B)[B");
    jbyteArray final_array = (jbyteArray)env->CallObjectMethod(cipher_object, methodId, data_byte);

    jsize final_size = env->GetArrayLength(final_array);
    jbyte* final = env->GetByteArrayElements(final_array,NULL);
    std::string final_str((const char*)final, final_size);

    env->ReleaseByteArrayElements(final_array, final, NULL);
    env->DeleteLocalRef(secret_class);
    env->DeleteLocalRef(key_factory_class);
    env->DeleteLocalRef(cipher_class);
    env->DeleteLocalRef(key_byte);
    env->DeleteLocalRef(data_byte);
    if (detached)
        g_jvm->DetachCurrentThread();
    return final_str;
}

std::string decryptDataWithPriKey(std::string& dataStr){
    unsigned char priKey[] = {
            0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcd, 0x8c, 0xed,
            0x23, 0xba, 0x3d, 0x94, 0x76, 0xf7, 0x1c, 0x7c, 0x11, 0x4e, 0xc8, 0x1a, 0xb5, 0x46, 0xc9,
            0xb2, 0x05, 0x13, 0x88, 0x67, 0x5f, 0x23, 0x08, 0xde, 0x16, 0x3e, 0x28, 0x0e, 0xbf, 0xc3,
            0x37, 0xf6, 0x2c, 0x10, 0xde, 0xc2, 0x58, 0x71, 0xa4, 0xb7, 0x4c, 0x99, 0x14, 0xa1, 0x48,
            0x28, 0xcc, 0x3e, 0x86, 0x17, 0xfa, 0x54, 0x18, 0xd0, 0x4a, 0xa5, 0x3d, 0xa4, 0x17, 0xc1,
            0x86, 0x10, 0x88, 0x50, 0xc1, 0xdd, 0x59, 0xbc, 0xcf, 0x0f, 0x85, 0x34, 0x02, 0x0b, 0x54,
            0xaf, 0x91, 0x79, 0xf8, 0x36, 0x3c, 0xa8, 0xe4, 0x74, 0x5e, 0x60, 0xc6, 0x0a, 0x23, 0x47,
            0xb7, 0xef, 0x3f, 0xbb, 0x5b, 0xb3, 0x09, 0x75, 0x8b, 0xb3, 0x29, 0xb7, 0x7c, 0xc4, 0x0a,
            0xf6, 0x41, 0x09, 0x65, 0xde, 0x88, 0xd4, 0xc5, 0xc3, 0x56, 0x5b, 0xc6, 0xa1, 0x4d, 0x64,
            0x8e, 0x06, 0x5f, 0x5b, 0xe0, 0x9f, 0x51, 0xbb, 0xe2, 0xab, 0xb3, 0x1d, 0x5b, 0x05, 0x63,
            0xc5, 0x93, 0xef, 0x4c, 0x3f, 0xd0, 0xb6, 0xbb, 0x2a, 0x00, 0x2e, 0xbb, 0x68, 0xd1, 0xc6,
            0x47, 0xda, 0x6c, 0xa7, 0xe4, 0x6d, 0xdf, 0xaf, 0x0d, 0xbd, 0x20, 0x56, 0xfa, 0x9f, 0x74,
            0xea, 0x36, 0x5e, 0x4e, 0x81, 0xee, 0x80, 0x50, 0xa9, 0xa2, 0xab, 0xfc, 0x36, 0xa3, 0x86,
            0x77, 0xd5, 0x89, 0xa7, 0x0f, 0x1f, 0xed, 0x6b, 0x66, 0x5f, 0x61, 0x5a, 0xb7, 0xd3, 0x08,
            0xf3, 0xba, 0x56, 0x15, 0x07, 0x2e, 0xa6, 0x31, 0x08, 0xce, 0x45, 0x91, 0x57, 0x95, 0x41,
            0xa3, 0xcb, 0xe1, 0x66, 0xb9, 0x70, 0x5c, 0x3e, 0x07, 0x75, 0x96, 0x01, 0x1b, 0xa4, 0x80,
            0x33, 0x6f, 0xdc, 0x0b, 0xb5, 0x9f, 0xb1, 0xce, 0x4b, 0xe5, 0x65, 0xf6, 0x2b, 0xa1, 0xef,
            0xb1, 0xa1, 0xb6, 0xc2, 0xd9, 0xd5, 0xc6, 0xc6, 0x1e, 0x9c, 0xf6, 0x65, 0xdf, 0x02, 0x03,
            0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc2, 0x0f, 0xd5, 0x2b, 0xaf, 0xff, 0xc7,
            0x95, 0x71, 0xc4, 0x30, 0xd6, 0x5e, 0x5c, 0xc9, 0xea, 0x6f, 0xc4, 0xa9, 0x0f, 0xe5, 0xdb,
            0x18, 0x4d, 0x57, 0xd4, 0x5d, 0x68, 0xfe, 0x91, 0xef, 0x2a, 0xd8, 0xf2, 0x92, 0xb6, 0x13,
            0xcf, 0x5c, 0x09, 0x08, 0x72, 0x0c, 0xa4, 0x82, 0xba, 0x59, 0x72, 0xb9, 0x21, 0xeb, 0xbd,
            0xca, 0x11, 0x8b, 0x28, 0x4a, 0x2e, 0xcf, 0x47, 0x1d, 0x0f, 0x58, 0xa4, 0x6c, 0x23, 0x66,
            0xab, 0x41, 0x82, 0x21, 0xa2, 0x13, 0xf3, 0x1c, 0xa0, 0xf9, 0x75, 0xa0, 0xb4, 0x66, 0x45,
            0x13, 0x5f, 0xbd, 0xcc, 0xc2, 0x99, 0x00, 0x20, 0xb9, 0x1d, 0x89, 0xee, 0x7c, 0x30, 0xdd,
            0x80, 0xbb, 0xcd, 0xa8, 0x6e, 0x96, 0x5e, 0x42, 0x5f, 0xc6, 0xee, 0xda, 0x83, 0x98, 0x8d,
            0xd6, 0xc5, 0xb4, 0xac, 0x69, 0xb9, 0xb4, 0xb8, 0x19, 0x3d, 0xea, 0x3b, 0xb4, 0x84, 0x7f,
            0x46, 0x26, 0xe3, 0x42, 0xd1, 0x8e, 0x66, 0xde, 0x9f, 0xb5, 0xf8, 0x6d, 0x31, 0x60, 0xa0,
            0xaa, 0x3c, 0xcd, 0x76, 0x47, 0x90, 0x9a, 0x2e, 0x63, 0xb1, 0x8f, 0x20, 0x89, 0x64, 0x1e,
            0xa2, 0x80, 0x3e, 0xf0, 0x8d, 0x51, 0xe0, 0x73, 0x89, 0xb6, 0x40, 0xbe, 0xc7, 0x19, 0xa6,
            0xc0, 0x04, 0x1e, 0x2d, 0xef, 0x3c, 0xe1, 0xd4, 0xc0, 0x3c, 0xf3, 0x0b, 0xf5, 0x95, 0xb3,
            0xab, 0x7e, 0xf4, 0x71, 0x40, 0x98, 0x9c, 0x61, 0x09, 0x62, 0xd9, 0x72, 0xb1, 0x1f, 0xb2,
            0x33, 0x8e, 0xa2, 0xa2, 0xd1, 0x39, 0xf3, 0x19, 0x25, 0x6b, 0x1f, 0x51, 0x8d, 0x3a, 0xb3,
            0xc7, 0x6e, 0xf0, 0x78, 0x9a, 0x01, 0x57, 0x38, 0x32, 0x17, 0xc1, 0x71, 0xdd, 0x80, 0x1b,
            0x29, 0xb9, 0xb7, 0xcc, 0x4d, 0xd3, 0x8b, 0x6c, 0x2f, 0xe7, 0x4f, 0x42, 0x3b, 0x96, 0x98,
            0x26, 0x9c, 0xac, 0xd2, 0x20, 0x3a, 0x0b, 0x32, 0x81, 0x02, 0x81, 0x81, 0x00, 0xf4, 0x46,
            0x1c, 0x45, 0x7f, 0x8d, 0x26, 0x29, 0x89, 0xe2, 0x8e, 0x90, 0xff, 0xd3, 0xa1, 0x32, 0x86,
            0xcd, 0x55, 0xa9, 0x9c, 0x32, 0x1b, 0x73, 0xb8, 0x48, 0x9d, 0x72, 0x11, 0x9f, 0xde, 0x30,
            0x99, 0xb9, 0xdd, 0x53, 0x48, 0x20, 0x51, 0x18, 0x69, 0x2b, 0x8d, 0xca, 0xc1, 0x99, 0xbe,
            0x59, 0x91, 0x5d, 0x85, 0xe5, 0x15, 0x8f, 0x6d, 0x56, 0x5d, 0x97, 0x27, 0x58, 0x76, 0xb4,
            0xc3, 0x5b, 0x1a, 0x47, 0x86, 0xba, 0x21, 0x37, 0xe3, 0x67, 0x88, 0xb7, 0xdb, 0xba, 0x4c,
            0x88, 0xe9, 0xf9, 0x3c, 0x79, 0x57, 0x08, 0x87, 0xb2, 0x97, 0x40, 0x8b, 0xcc, 0x9c, 0x78,
            0xe5, 0x4e, 0x86, 0x6e, 0x8e, 0x72, 0x67, 0x7f, 0x32, 0xa3, 0xf9, 0xa1, 0xaa, 0x9d, 0x62,
            0x70, 0x37, 0x62, 0xdb, 0x08, 0x2e, 0x25, 0xad, 0x27, 0xaf, 0xe7, 0xc2, 0x7f, 0x92, 0xbe,
            0x6f, 0x08, 0x39, 0x91, 0x7e, 0x61, 0x02, 0x81, 0x81, 0x00, 0xd7, 0x6a, 0xf1, 0x6c, 0xa0,
            0x7f, 0xe8, 0xc8, 0xc9, 0x43, 0x63, 0x70, 0xab, 0x5c, 0x46, 0x49, 0x27, 0xe1, 0xa0, 0xc6,
            0x13, 0xd5, 0xe5, 0x21, 0x01, 0xea, 0x51, 0x31, 0x11, 0x95, 0xf7, 0x45, 0x6d, 0x23, 0xbc,
            0xca, 0x7a, 0x8a, 0x98, 0x54, 0x20, 0x29, 0x1b, 0x69, 0x45, 0xe6, 0x8f, 0x6e, 0x27, 0xfd,
            0x2f, 0x9d, 0xc2, 0xe0, 0xe5, 0x6a, 0xd0, 0x81, 0xa6, 0x2d, 0xb1, 0x4e, 0x5e, 0x6d, 0x27,
            0x70, 0x8e, 0xfe, 0xfa, 0x48, 0xdc, 0x72, 0x23, 0x37, 0xf8, 0x0e, 0x45, 0x3e, 0xae, 0xb6,
            0x6f, 0x04, 0xeb, 0x0a, 0xcc, 0xa4, 0x01, 0xc7, 0x34, 0x80, 0x08, 0xec, 0x14, 0x16, 0xac,
            0x1b, 0x1e, 0xc8, 0x0d, 0xdd, 0x24, 0x2f, 0x26, 0x67, 0xfb, 0xb6, 0xa1, 0x43, 0x8f, 0x88,
            0x80, 0xf3, 0x85, 0x45, 0x1e, 0x9c, 0x77, 0xf0, 0xe5, 0x78, 0x85, 0x09, 0x0e, 0x89, 0x88,
            0x53, 0xcc, 0x3f, 0x02, 0x81, 0x80, 0x52, 0x29, 0xf3, 0x00, 0x7d, 0x72, 0xe0, 0xcf, 0x40,
            0x0d, 0xf0, 0x9e, 0x5d, 0x2e, 0xb6, 0x1d, 0xe4, 0xb1, 0xd4, 0x8a, 0x84, 0x7b, 0x66, 0x38,
            0x7a, 0x58, 0x12, 0x7d, 0x77, 0xe8, 0x2a, 0x38, 0x76, 0xbc, 0xc9, 0xf1, 0x65, 0x65, 0x59,
            0x61, 0xb8, 0x9e, 0x69, 0xc7, 0x35, 0x6f, 0x9d, 0x53, 0x4b, 0x4e, 0x05, 0xe7, 0x94, 0x64,
            0xf6, 0x06, 0x02, 0xdd, 0x00, 0xe3, 0x04, 0xaa, 0xb0, 0xbb, 0x48, 0x0f, 0x9f, 0x05, 0xa4,
            0x7e, 0xc4, 0x02, 0xe3, 0x3d, 0xd4, 0xae, 0xc9, 0x67, 0x94, 0x2b, 0xbd, 0x67, 0xa3, 0x1a,
            0xbf, 0x6a, 0x16, 0xee, 0x23, 0x17, 0xe3, 0xd9, 0xd6, 0x67, 0x9f, 0x58, 0x38, 0x99, 0xca,
            0xae, 0x42, 0x3e, 0x5d, 0x8d, 0x3f, 0x72, 0x48, 0xd6, 0x2e, 0x0b, 0x16, 0x59, 0x9e, 0x0c,
            0x16, 0x3e, 0x2f, 0x30, 0xe9, 0x7f, 0x37, 0xc0, 0xce, 0x60, 0x19, 0xdd, 0x12, 0x81, 0x02,
            0x81, 0x80, 0x58, 0x09, 0xbc, 0xe1, 0x48, 0x36, 0xfe, 0x4c, 0x10, 0xf5, 0x19, 0x8e, 0xd2,
            0x79, 0xc3, 0xbf, 0xe2, 0x2c, 0xb4, 0x28, 0x3f, 0xb3, 0x0b, 0x11, 0x92, 0x56, 0xd1, 0x17,
            0xdc, 0xb8, 0x0d, 0x76, 0xb2, 0x44, 0x08, 0xc4, 0x37, 0x90, 0xac, 0xf0, 0xb4, 0xb4, 0x18,
            0x1f, 0xce, 0x11, 0x8c, 0x4c, 0xd8, 0xcb, 0x00, 0xca, 0xd8, 0xfa, 0x50, 0xc8, 0x76, 0xae,
            0x85, 0xdb, 0xe6, 0xba, 0xc0, 0x9c, 0x9b, 0xa1, 0xc4, 0xcf, 0x30, 0x3a, 0xd6, 0xdd, 0x4e,
            0xc7, 0x70, 0xf9, 0x64, 0x13, 0x5a, 0x13, 0xf5, 0x0b, 0x6d, 0x83, 0xdc, 0x5e, 0xaa, 0xdb,
            0x5e, 0xf9, 0x74, 0xac, 0x07, 0x09, 0xbd, 0x0c, 0xd8, 0x67, 0xaa, 0x42, 0xd6, 0xa6, 0xee,
            0x6b, 0x50, 0xd4, 0x32, 0xd4, 0x09, 0xb5, 0x1f, 0xfe, 0x66, 0x58, 0xf9, 0x49, 0xb9, 0x3b,
            0x1a, 0x8d, 0x46, 0xd1, 0x8c, 0xbf, 0x68, 0x97, 0xd6, 0xc1, 0x02, 0x81, 0x80, 0x4b, 0x95,
            0x61, 0x89, 0xe6, 0xbb, 0x85, 0x53, 0x47, 0x37, 0x99, 0x24, 0x2f, 0x82, 0x06, 0xc4, 0x50,
            0x77, 0x8e, 0x92, 0xe1, 0xa1, 0xc0, 0x42, 0x5f, 0xd4, 0x8f, 0x37, 0x58, 0x1c, 0x06, 0xac,
            0xfb, 0x05, 0x74, 0x00, 0x49, 0xc9, 0x97, 0xcd, 0xb5, 0x77, 0x96, 0x4a, 0x7a, 0x39, 0x5d,
            0x94, 0xca, 0x39, 0x05, 0xcf, 0xae, 0xe9, 0x87, 0x8c, 0x0e, 0xbd, 0x52, 0x79, 0x6f, 0xa3,
            0xff, 0xd7, 0x44, 0x05, 0x1d, 0x96, 0x13, 0x0c, 0xe8, 0x33, 0xa6, 0x46, 0x56, 0xaf, 0x41,
            0xeb, 0x0d, 0xec, 0xaa, 0x4e, 0xc3, 0x71, 0x9c, 0x8b, 0x02, 0x06, 0x3d, 0x3c, 0xca, 0xc1,
            0xd2, 0x84, 0xe8, 0x1c, 0xc2, 0x07, 0x99, 0xc5, 0x40, 0x31, 0x82, 0x62, 0xd1, 0xfe, 0xdd,
            0xc5, 0x39, 0xd4, 0x30, 0xc1, 0x31, 0x2d, 0xfb, 0xdc, 0x46, 0xae, 0xb0, 0xb3, 0xab, 0x78,
            0xfb, 0x10, 0x5e, 0x5a, 0xee, 0xaf
    };

    JNIEnv *env = NULL;
    bool detached = g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (detached)
        g_jvm->AttachCurrentThread(&env, NULL);

    jsize key_size = sizeof (priKey);
    jbyte* key = (jbyte*)priKey;
    jbyteArray key_byte = env->NewByteArray(key_size);
    env->SetByteArrayRegion(key_byte,0, key_size, key);

    jsize data_size = dataStr.length();
    jbyte* data = (jbyte*)dataStr.c_str();
    jbyteArray data_byte = env->NewByteArray(data_size);
    env->SetByteArrayRegion(data_byte,0, data_size, data);

    //PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pubArray);
    jclass secret_class = env->FindClass("java/security/spec/PKCS8EncodedKeySpec");
    jmethodID methodId=env->GetMethodID(secret_class, "<init>", "([B)V");
    jobject secret_object = env->NewObject(secret_class, methodId, key_byte);

    //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    jclass key_factory_class = env->FindClass("java/security/KeyFactory");
    methodId = env->GetStaticMethodID(key_factory_class, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyFactory;");
    jstring rsa_string = env->NewStringUTF("RSA");
    jobject key_factory_object = env->CallStaticObjectMethod(key_factory_class, methodId, rsa_string);

    //privateKey = keyFactory.generatePrivate(privateKeySpec);
    methodId = env->GetMethodID(key_factory_class, "generatePrivate", "(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;");
    jobject pubkey_object = env->CallObjectMethod(key_factory_object, methodId, secret_object);

    //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    jclass cipher_class = env->FindClass("javax/crypto/Cipher");
    methodId = env->GetStaticMethodID(cipher_class, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jstring rsa_mode_string = env->NewStringUTF("RSA/ECB/PKCS1Padding");
    jobject cipher_object = env->CallStaticObjectMethod(cipher_class, methodId, rsa_mode_string);

    //cipher.init(Cipher.DECRYPT_MODE, skeySpec);
    methodId = env->GetMethodID(cipher_class, "init", "(ILjava/security/Key;)V");
    env->CallVoidMethod(cipher_object, methodId, 2, pubkey_object);

    //cipher.doFinal(bytIn);
    methodId = env->GetMethodID(cipher_class, "doFinal", "([B)[B");
    jbyteArray final_array = (jbyteArray)env->CallObjectMethod(cipher_object, methodId, data_byte);

    jsize final_size = env->GetArrayLength(final_array);
    jbyte* final = env->GetByteArrayElements(final_array,NULL);
    std::string final_str((const char*)final, final_size);

    env->ReleaseByteArrayElements(final_array, final, NULL);
    env->DeleteLocalRef(secret_class);
    env->DeleteLocalRef(key_factory_class);
    env->DeleteLocalRef(cipher_class);
    env->DeleteLocalRef(key_byte);
    env->DeleteLocalRef(data_byte);
    if (detached)
        g_jvm->DetachCurrentThread();
    return final_str;
}

#else

std::string opensslGenerateRandomAESKey() {
    int ret = 0;
    unsigned char key[AES_KEY_LENGTH];
    do {
        uint64 currTime = getCurrTimestamp();
        std::string timeStr = std::to_string(currTime);
        RAND_seed(timeStr.c_str(), timeStr.length());
        ret = RAND_bytes(key, sizeof(key));
    } while (ret != 1);
    return std::string((const char*)key, sizeof (key));
}

std::string opensslEncryptDataWithAES(std::string& aesKey, std::string& dataStr) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, (const unsigned char*)aesKey.c_str(), NULL);
    unsigned char* result = (unsigned char*)malloc(dataStr.length() + AES_KEY_LENGTH * 8);
    int len1 = dataStr.length();
    EVP_EncryptUpdate(ctx, result, &len1, (const unsigned char*)dataStr.c_str(), dataStr.length());
    int len2 = 0;
    EVP_EncryptFinal_ex(ctx, result + len1, &len2);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    std::string res((char*)result, len1 + len2);
    free(result);
    return res;
}

std::string opensslDescryptDataWithAES(std::string& aesKey, std::string& dataStr) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, (const unsigned char*)aesKey.c_str(), NULL);
    unsigned char* result = (unsigned char*)malloc(dataStr.length() + AES_KEY_LENGTH * 8);
    int len1 = dataStr.length();
    int ret = EVP_DecryptUpdate(ctx, result, &len1, (const unsigned char*)dataStr.c_str(), dataStr.length());
    if(ret != 1) {
        LOGD("opensslDescryptDataWithAES failed!");
        free(result);
        return dataStr;
    }
    int len2 = 0;
    ret = EVP_DecryptFinal_ex(ctx, result + len1, &len2);
    if(ret != 1) {
        LOGD("opensslDescryptDataWithAES failed!");
        free(result);
        return dataStr;
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    std::string res((char*)result, len1 + len2);
    free(result);
    return res;
}

std::string opensslEncryptDataWithPubKey(std::string& dataStr) {
    unsigned char pubKey[] = {
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xcd, 0x8c, 0xed, 0x23, 0xba, 0x3d, 0x94, 0x76, 0xf7, 0x1c, 0x7c, 0x11, 0x4e, 0xc8, 0x1a,
        0xb5, 0x46, 0xc9, 0xb2, 0x05, 0x13, 0x88, 0x67, 0x5f, 0x23, 0x08, 0xde, 0x16, 0x3e, 0x28, 0x0e,
        0xbf, 0xc3, 0x37, 0xf6, 0x2c, 0x10, 0xde, 0xc2, 0x58, 0x71, 0xa4, 0xb7, 0x4c, 0x99, 0x14, 0xa1,
        0x48, 0x28, 0xcc, 0x3e, 0x86, 0x17, 0xfa, 0x54, 0x18, 0xd0, 0x4a, 0xa5, 0x3d, 0xa4, 0x17, 0xc1,
        0x86, 0x10, 0x88, 0x50, 0xc1, 0xdd, 0x59, 0xbc, 0xcf, 0x0f, 0x85, 0x34, 0x02, 0x0b, 0x54, 0xaf,
        0x91, 0x79, 0xf8, 0x36, 0x3c, 0xa8, 0xe4, 0x74, 0x5e, 0x60, 0xc6, 0x0a, 0x23, 0x47, 0xb7, 0xef,
        0x3f, 0xbb, 0x5b, 0xb3, 0x09, 0x75, 0x8b, 0xb3, 0x29, 0xb7, 0x7c, 0xc4, 0x0a, 0xf6, 0x41, 0x09,
        0x65, 0xde, 0x88, 0xd4, 0xc5, 0xc3, 0x56, 0x5b, 0xc6, 0xa1, 0x4d, 0x64, 0x8e, 0x06, 0x5f, 0x5b,
        0xe0, 0x9f, 0x51, 0xbb, 0xe2, 0xab, 0xb3, 0x1d, 0x5b, 0x05, 0x63, 0xc5, 0x93, 0xef, 0x4c, 0x3f,
        0xd0, 0xb6, 0xbb, 0x2a, 0x00, 0x2e, 0xbb, 0x68, 0xd1, 0xc6, 0x47, 0xda, 0x6c, 0xa7, 0xe4, 0x6d,
        0xdf, 0xaf, 0x0d, 0xbd, 0x20, 0x56, 0xfa, 0x9f, 0x74, 0xea, 0x36, 0x5e, 0x4e, 0x81, 0xee, 0x80,
        0x50, 0xa9, 0xa2, 0xab, 0xfc, 0x36, 0xa3, 0x86, 0x77, 0xd5, 0x89, 0xa7, 0x0f, 0x1f, 0xed, 0x6b,
        0x66, 0x5f, 0x61, 0x5a, 0xb7, 0xd3, 0x08, 0xf3, 0xba, 0x56, 0x15, 0x07, 0x2e, 0xa6, 0x31, 0x08,
        0xce, 0x45, 0x91, 0x57, 0x95, 0x41, 0xa3, 0xcb, 0xe1, 0x66, 0xb9, 0x70, 0x5c, 0x3e, 0x07, 0x75,
        0x96, 0x01, 0x1b, 0xa4, 0x80, 0x33, 0x6f, 0xdc, 0x0b, 0xb5, 0x9f, 0xb1, 0xce, 0x4b, 0xe5, 0x65,
        0xf6, 0x2b, 0xa1, 0xef, 0xb1, 0xa1, 0xb6, 0xc2, 0xd9, 0xd5, 0xc6, 0xc6, 0x1e, 0x9c, 0xf6, 0x65,
        0xdf, 0x02, 0x03, 0x01, 0x00, 0x01
    };

    const unsigned char* key = (const unsigned char*)pubKey;
    RSA * rsa = d2i_RSA_PUBKEY(NULL, &key, RSA_PUBLIC_KEY_LENGTH);
    unsigned char rsa_out_buffer[RSA_LENGTH];
    int len = RSA_public_encrypt(dataStr.length(), (const unsigned char *)dataStr.c_str(), (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_PADDING);
    if (len != RSA_LENGTH) {
        return "";
    }
    return std::string((const char*)rsa_out_buffer, RSA_LENGTH);
}
#endif //__USE_JNI_ENCRYPT__

void auth_init(JNIEnv *env, jclass clazz, jobject context, jstring appId) {
    generateOppoSign(env, clazz, context);
    const char *appId_c = env->GetStringUTFChars(appId, NULL);
    if(g_appId_c)
        free(g_appId_c);
    int length = strlen(appId_c) + 1;
    g_appId_c = (char*)malloc(length);
    memset(g_appId_c, 0, length);
    memcpy(g_appId_c, appId_c, length - 1);

    env->ReleaseStringUTFChars(appId, appId_c);
}

struct recvDataStruct {
    char *data;
    size_t size;
};

static size_t auth_curl_write_data(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct recvDataStruct *mem = (struct recvDataStruct *)userp;
    mem->data = (char*)realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        return 0;
    }
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    LOGD("received size %d", mem->size);
    return realsize;
}

#if __USE_ONEWAY_CERTIFICATION__
void valid_ca_file(std::string& caCertFile){
    FILE *fp = fopen(caCertFile.c_str(), "r");
    if(fp == NULL){
        FILE *fp = fopen(caCertFile.c_str(),"wb");
        if (!fp) {
            LOGD("can't create file: %s", caCertFile.c_str());
            return ;
        }
        fseek(fp, 0, SEEK_SET);
        int len = fwrite(openca, get_open_ca_size(), 1, fp);
        LOGD("valid_ca_file fwrite size [%d]", len);
        fclose(fp);
    }
}
#endif

// URLCheck  | SysSafeCheck | LogSafe
bool auth_service(const char* serviceId) {
    //判断是否进行过初始化
    if (g_appId_c == NULL || g_oppoSign_c == NULL) {
        LOGD("auth is not inited!");
        return false;
    }

    //判断是否有缓存数据
    std::map<std::string, bool>::iterator it = gAuthMap.find(serviceId);
    if (it != gAuthMap.end() && it->second) {
        return true;
    }
    
    //请求网络获取数据
    //{"code":"0","message":"success","data":{"authorized":true,"expireIn":600}}
    std::string data = get_service_data(serviceId, "{}");

    //解析返回的鉴权结果Json数据
    CJsonObject resp;
    if(data.length() == 0 || resp.Parse(data) == false){
        LOGD("curl recieved data is not a json!");
        return false;
    }

    std::string code = "";
    bool authorized;
    if (resp.Get("code", code) && strcmp(code.c_str(), "0") == 0 &&
        resp.KeyExist("data") && resp["data"].Get("authorized", authorized) && authorized) {
        LOGD("authorized success！");

        //鉴权成功后插入缓存数据
        _threadMutex.lock();
        gAuthMap.insert(std::pair<std::string, bool>(serviceId, true));
        _threadMutex.unlock();
        return true;
    }

    //鉴权失败打印错误码
    LOGD("resp errno:[%s]", code.c_str());
    return false;
}

std::string get_service_data(const char* serviceId, const char* param)
{
    std::string nil("");
    if(g_appId_c == NULL || g_oppoSign_c == NULL) {
        LOGD("auth is not inited!");
        return nil;
    }

    CURL *curl;
    CURLcode res;

    struct recvDataStruct chunk;
    chunk.data = (char*)malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl == NULL) {
        LOGD("curl init fail");
        if(chunk.data) {
            free(chunk.data);
            chunk.data = NULL;
        }
        return nil;
    }

    uint64 currTime = getCurrTimestamp();
    std::string packName = getPackageName();

    int bufLen = strlen("appPackage=") + packName.length()
            + strlen("&appSign=") + strlen(g_oppoSign_c)
            + strlen("&param=") + strlen(param)
            + strlen("&serviceId=") + strlen(serviceId)
            + strlen("&timestamp=") + std::to_string(currTime).length()
            + 1;
    LOGD("bufLen:[%d]", bufLen);
    char* buf = (char*)malloc(bufLen);
    memset(buf, 0, bufLen);
    snprintf(buf, bufLen, "appPackage=%s&appSign=%s&param=%s&serviceId=%s&timestamp=%lld",
             packName.c_str(), g_oppoSign_c, param, serviceId, currTime);

    LOGD("buf:[%s]", buf);
    std::string md5 = MD5(buf, strlen(buf)).toString();
    LOGD("md5:[%s]", md5.c_str());
    free(buf);

    int varLen = strlen(g_appId_c) + packName.length() + strlen(g_oppoSign_c) + strlen(AUTH_VERNO)
            + strlen(param) + strlen(serviceId) + std::to_string(currTime).length() + md5.length() ;

    char* fmt = "{\"appId\":\"%s\",\"appPackage\":\"%s\",\"appSign\":\"%s\",\"authver\":\"%s\",\"param\":%s,\"serviceId\":\"%s\",\"timestamp\":%lld,\"sign\":\"%s\"}";
    int reqLen = varLen + strlen(fmt) + 1;
    char* reqStr = (char*)malloc(reqLen);
    memset(reqStr, 0, reqLen);
    snprintf(reqStr, reqLen, fmt,
             g_appId_c, packName.c_str(), g_oppoSign_c, AUTH_VERNO, param, serviceId, currTime, md5.c_str());
    LOGD("reqStr:[%s]", reqStr);
    std::string reqContent(reqStr);
    free(reqStr);

#if __USE_JNI_ENCRYPT__
    std::string aesKey = generateRandomAESKey();
    std::string encryptKey = encryptDataWithPubKey(aesKey);
    std::string encryptReq = encryptDataWithAES(aesKey, reqContent);
#else
    std::string aesKey = opensslGenerateRandomAESKey();
    std::string encryptKey = opensslEncryptDataWithPubKey(aesKey);
    std::string encryptReq = opensslEncryptDataWithAES(aesKey, reqContent);
#endif

    int length = encryptKey.length();
    unsigned char array[4] = {0};
    array[0] = (length >> 24) & 0xFF;
    array[1] = (length >> 16) & 0xFF;
    array[2] = (length >> 8) & 0xFF;
    array[3] = length & 0xFF;
    std::string lenStr((const char*)array, 4);
    std::string finalStr = lenStr + encryptKey + encryptReq;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type:application/octet-stream");

    //"http://10.176.86.213:9012/api/server/app-open-auth"  //测试服
    /*char authUrl[] = {
            0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x31,0x30,0x2E,0x31,0x37,0x36,0x2E,0x38,0x36,0x2E,
            0x32,0x31,0x33,0x3A,0x39,0x30,0x31,0x32,0x2F,0x61,0x70,0x69,0x2F,0x73,0x65,0x72,0x76,
            0x65,0x72,0x2F,0x61,0x70,0x70,0x2D,0x6F,0x70,0x65,0x6E,0x2D,0x61,0x75,0x74,0x68,0x00
    };*/

    //"https://infrasec-openapi-cn.heytapmobi.com/api/server/app-open-auth"  //正式服
    char authUrl[] = {
            0x68,0x74,0x74,0x70,0x73,0x3A,0x2F,0x2F,0x69,0x6E,0x66,0x72,0x61,0x73,0x65,0x63,0x2D,
            0x6F,0x70,0x65,0x6E,0x61,0x70,0x69,0x2D,0x63,0x6E,0x2E,0x68,0x65,0x79,0x74,0x61,0x70,
            0x6D,0x6F,0x62,0x69,0x2E,0x63,0x6F,0x6D,0x2F,0x61,0x70,0x69,0x2F,0x73,0x65,0x72,0x76,
            0x65,0x72,0x2F,0x61,0x70,0x70,0x2D,0x6F,0x70,0x65,0x6E,0x2D,0x61,0x75,0x74,0x68,0x00
    };

    curl_easy_setopt(curl, CURLOPT_URL, authUrl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, true);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, finalStr.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, finalStr.length());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_curl_write_data);

#if __USE_ONEWAY_CERTIFICATION__
    // 验证服务器证书有效性
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    // 检验证书中的主机名和你访问的主机名一致
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
    // 指定 CA 证书路径
    std::string caCertFile = "/data/data/" + getPackageName() + "/cache/stdscoauthca";
    _threadMutex.lock();
    valid_ca_file(caCertFile);
    _threadMutex.unlock();
    curl_easy_setopt(curl, CURLOPT_CAINFO, caCertFile.c_str());
#else
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if(chunk.data == NULL) {
        LOGD("curl recieved data is null!");
        return nil;
    }
    if (res != 0) {
        if(chunk.data) {
            free(chunk.data);
            chunk.data = NULL;
        }
        LOGD("curl failed, err[%d]!", res);
        return nil;
    }

    std::string resp(chunk.data, chunk.size);
#if __USE_JNI_ENCRYPT__
    std::string data = descryptDataWithAES(aesKey, resp);
#else
    std::string data = opensslDescryptDataWithAES(aesKey, resp);
#endif //__USE_JNI_ENCRYPT__

    if(chunk.data) {
        free(chunk.data);
        chunk.data = NULL;
    }
    LOGD("curl finish, recieved data:[%s]!", data.c_str());
    return data;
}
