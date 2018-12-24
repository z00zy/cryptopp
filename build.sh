#!/bin/bash

export ANDROID_NDK_ROOT="$HOME/Library/Android/android-ndk-r16b"
export ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"

OUTPUT="$PWD/out"

for arch in armeabi-v7a arm64-v8a; do
    if [ -e "$OUTPUT/$arch" ]; then
        rm -rf "$OUTPUT/$arch"
    fi

    AOSP_API_VERSION="21" source setenv-android-gcc.sh $arch

    if [ "$?" -eq "0" ]; then
        make -f GNUmakefile-cross distclean
        make -j -f GNUmakefile-cross static dynamic
        make -f GNUmakefile-cross install-lib PREFIX="$OUTPUT/$arch"
        $STRIP --strip-debug $OUTPUT/$arch/lib/libcryptopp.a
        $STRIP --strip-debug $OUTPUT/$arch/lib/libcryptopp.so
    fi
done

