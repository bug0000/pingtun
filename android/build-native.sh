#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
ndk=${ANDROID_NDK_HOME:-$sdk/ndk/28.2.13676358}
toolchain=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
test -x "$toolchain/aarch64-linux-android29-clang"
cd "$root"
for abi in arm64-v8a x86_64; do
 case "$abi" in
  arm64-v8a) arch=arm64; compiler=aarch64-linux-android29-clang ;;
  x86_64) arch=amd64; compiler=x86_64-linux-android29-clang ;;
 esac
 out=$root/android/app/src/main/jniLibs/$abi
 mkdir -p "$out"
 GOOS=android GOARCH="$arch" CGO_ENABLED=1 CC="$toolchain/$compiler" go build -trimpath -buildmode=c-shared \
   -ldflags='-s -w -extldflags=-Wl,-z,max-page-size=16384' -o "$out/libpingtun.so" ./mobile/jni
 rm "$out/libpingtun.h"
done
