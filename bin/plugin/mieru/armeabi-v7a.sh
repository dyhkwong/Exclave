#!/bin/bash

source "bin/init/env.sh"
source "bin/plugin/mieru/init.sh"

DIR="$ROOT/armeabi-v7a"
mkdir -p $DIR
env CC=$ANDROID_ARM_CC GOARCH=arm GOARM=7 go build -v -o $DIR/$LIB_OUTPUT -buildvcs=false -trimpath -ldflags "-X 'github.com/enfein/mieru/pkg/log.LogPrefix=C ' -s -w -buildid=" ./cmd/mieru

