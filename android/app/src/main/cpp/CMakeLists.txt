cmake_minimum_required(VERSION 3.22.1)
project(numbercipher C)

add_library(numbercipher SHARED
    jni_bridge.c
    pbkdf2_sha256.c
    sha256_portable.c
    sha256_armv8.c
    sha256_shani.c)

target_compile_options(numbercipher PRIVATE -O3 -Wall -Wextra -fvisibility=hidden)

# Hardware SHA-256 code paths are compiled with the needed instruction sets and only
# used after a runtime CPU check, so the library still runs on CPUs without them.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set_source_files_properties(sha256_armv8.c PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
elseif(ANDROID_ABI STREQUAL "x86_64" OR ANDROID_ABI STREQUAL "x86")
    set_source_files_properties(sha256_shani.c PROPERTIES COMPILE_OPTIONS "-msse4.1;-mssse3;-msha")
endif()

# 16 KB page alignment (required on Android 15+ devices that use 16 KB pages).
target_link_options(numbercipher PRIVATE "-Wl,-z,max-page-size=16384")
