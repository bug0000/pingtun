//go:build android

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include "_cgo_export.h"
#include "bridge.h"

static JavaVM *vm;
static jobject service;
static pthread_mutex_t service_lock = PTHREAD_MUTEX_INITIALIZER;

static void clear_service(JNIEnv *env) {
    pthread_mutex_lock(&service_lock);
    if (service) { (*env)->DeleteGlobalRef(env, service); service = NULL; }
    pthread_mutex_unlock(&service_lock);
}
static jstring result_string(JNIEnv *env, char *result) {
    if (!result) return NULL;
    jstring value = (*env)->NewStringUTF(env, result);
    free(result);
    return value;
}

int pt_protect_socket(int fd) {
    JNIEnv *env = NULL;
    if (!vm) return 0;
    int attached = 0;
    jint status = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) return 0;
        attached = 1;
    } else if (status != JNI_OK) return 0;
    pthread_mutex_lock(&service_lock);
    jobject local = service ? (*env)->NewLocalRef(env, service) : NULL;
    pthread_mutex_unlock(&service_lock);
    jboolean protected = JNI_FALSE;
    if (local) {
        jclass cls = (*env)->GetObjectClass(env, local);
        jmethodID method = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
        if (method) protected = (*env)->CallBooleanMethod(env, local, method, (jint)fd);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); protected = JNI_FALSE; }
        (*env)->DeleteLocalRef(env, cls);
        (*env)->DeleteLocalRef(env, local);
    }
    if (attached) (*vm)->DetachCurrentThread(vm);
    return protected == JNI_TRUE;
}

JNIEXPORT jstring JNICALL Java_io_github_bug0000_pingtun_NativeEngine_start
  (JNIEnv *env, jclass cls, jint fd, jstring profile, jobject vpn) {
    (void)cls;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK) return (*env)->NewStringUTF(env, "JNI runtime unavailable");
    clear_service(env);
    pthread_mutex_lock(&service_lock);
    service = (*env)->NewGlobalRef(env, vpn);
    pthread_mutex_unlock(&service_lock);
    const char *text = (*env)->GetStringUTFChars(env, profile, NULL);
    if (!text) { clear_service(env); return NULL; }
    char *error = ptStart(fd, (char *)text);
    (*env)->ReleaseStringUTFChars(env, profile, text);
    if (error) clear_service(env);
    return result_string(env, error);
}
JNIEXPORT void JNICALL Java_io_github_bug0000_pingtun_NativeEngine_stop
  (JNIEnv *env, jclass cls) { (void)cls; ptStop(); clear_service(env); }
JNIEXPORT jstring JNICALL Java_io_github_bug0000_pingtun_NativeEngine_snapshot
  (JNIEnv *env, jclass cls) { (void)cls; return result_string(env, ptSnapshot()); }
JNIEXPORT jstring JNICALL Java_io_github_bug0000_pingtun_NativeEngine_inspect
  (JNIEnv *env, jclass cls, jstring profile) {
    (void)cls;
    const char *text = (*env)->GetStringUTFChars(env, profile, NULL);
    if (!text) return NULL;
    char *value = ptInspect((char *)text);
    (*env)->ReleaseStringUTFChars(env, profile, text);
    return result_string(env, value);
}
JNIEXPORT jstring JNICALL Java_io_github_bug0000_pingtun_NativeEngine_probeSocket
  (JNIEnv *env, jclass cls) { (void)cls; return result_string(env, ptProbe()); }
