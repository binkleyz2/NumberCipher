// JNI glue for io.github.binkleyz2.numbercipher.crypto.NativeKdf
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2_sha256.h"

typedef struct {
    JNIEnv *env;
    jobject callback;
    jmethodID on_chunk;
} cb_ctx;

static int on_chunk(void *p, uint32_t done) {
    cb_ctx *c = (cb_ctx *)p;
    jint r = (*c->env)->CallIntMethod(c->env, c->callback, c->on_chunk, (jint)done);
    if ((*c->env)->ExceptionCheck(c->env)) return -1;  // let the exception surface in Kotlin
    return r;
}

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

JNIEXPORT jint JNICALL
Java_io_github_binkleyz2_numbercipher_crypto_NativeKdf_nativeDerive(
        JNIEnv *env, jclass cls, jbyteArray jpw, jbyteArray jsalt, jint max_rounds, jint chunk,
        jbyteArray jout, jobject callback) {
    (void)cls;
    if (max_rounds < 1 || chunk < 1 || (*env)->GetArrayLength(env, jout) < 32) return 0;

    jsize pw_len = (*env)->GetArrayLength(env, jpw);
    jsize salt_len = (*env)->GetArrayLength(env, jsalt);
    uint8_t *pw = malloc(pw_len ? (size_t)pw_len : 1);
    uint8_t *salt = malloc(salt_len ? (size_t)salt_len : 1);
    uint8_t out[32];
    if (!pw || !salt) { free(pw); free(salt); return 0; }
    (*env)->GetByteArrayRegion(env, jpw, 0, pw_len, (jbyte *)pw);
    (*env)->GetByteArrayRegion(env, jsalt, 0, salt_len, (jbyte *)salt);

    cb_ctx ctx = {env, callback, NULL};
    jclass cb_cls = (*env)->GetObjectClass(env, callback);
    ctx.on_chunk = (*env)->GetMethodID(env, cb_cls, "onChunk", "(I)I");
    (*env)->DeleteLocalRef(env, cb_cls);

    uint32_t done = 0;
    if (ctx.on_chunk) {
        done = nc_pbkdf2_sha256(pw, (size_t)pw_len, salt, (size_t)salt_len, (uint32_t)max_rounds,
                                (uint32_t)chunk, out, on_chunk, &ctx);
        (*env)->SetByteArrayRegion(env, jout, 0, 32, (const jbyte *)out);
    }

    wipe(out, sizeof out);
    wipe(pw, (size_t)pw_len);
    free(pw);
    free(salt);
    return (jint)done;
}

JNIEXPORT jstring JNICALL
Java_io_github_binkleyz2_numbercipher_crypto_NativeKdf_nativeBackendName(JNIEnv *env, jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, nc_backend_name(nc_active_backend()));
}
