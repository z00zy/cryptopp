#!/bin/bash

export ANDROID_NDK_ROOT="$HOME/android/android-ndk-r16b"
export ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"

OUTPUT="$PWD/out"

for arch in arm64-v8a armeabi-v7a x86_64
do
    if [ "$arch" = "arm64-v8a" ]; then
        AOSP_API_VERSION="21" source setenv-android-gcc.sh $arch
    else
        AOSP_API_VERSION="19" source setenv-android-gcc.sh $arch
    fi

    if [ ! -e "$OUTPUT" ]; then
        mkdir "$OUTPUT"
    else
        rm -rf "$OUTPUT/$arch"
    fi

    if [ "$?" -eq "0" ]; then
        make -f GNUmakefile-cross distclean
        make -j -f GNUmakefile-cross static dynamic
        make -f GNUmakefile-cross install-lib PREFIX="$OUTPUT/$arch"
    fi
done
