#!/bin/bash

source "bin/init/env.sh"
source "bin/plugin/mieru/init.sh"

DIR="$ROOT/x86"
mkdir -p $DIR
env CC=$ANDROID_X86_CC GOARCH=386 go build -v -o $DIR/$LIB_OUTPUT -buildvcs=false -trimpath -ldflags "-X 'github.com/enfein/mieru/pkg/log.LogPrefix=C ' -s -w -buildid=" ./cmd/mieru
