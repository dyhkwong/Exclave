#!/bin/bash

if [[ "$OSTYPE" =~ ^darwin ]]; then
  export PROJECT=$PWD
else
  export PROJECT=$(realpath .)
fi

export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
export ANDROID_ARM_CC=$TOOLCHAIN/armv7a-linux-androideabi21-clang
export ANDROID_ARM64_CC=$TOOLCHAIN/aarch64-linux-android21-clang
export ANDROID_X86_CC=$TOOLCHAIN/i686-linux-android21-clang
export ANDROID_X86_64_CC=$TOOLCHAIN/x86_64-linux-android21-clang

export ANDROID_LD=$TOOLCHAIN/ld
export ANDROID_AR=$TOOLCHAIN/llvm-ar
