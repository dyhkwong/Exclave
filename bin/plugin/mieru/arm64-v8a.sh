#!/bin/bash

source "bin/init/env.sh"
source "bin/plugin/mieru/init.sh"

DIR="$ROOT/arm64-v8a"
mkdir -p $DIR
env CC=$ANDROID_ARM64_CC GOARCH=arm64 go build -v -o $DIR/$LIB_OUTPUT -buildvcs=false -trimpath -ldflags "-X 'github.com/enfein/mieru/pkg/log.LogPrefix=C ' -s -w -buildid=" ./cmd/mieru
