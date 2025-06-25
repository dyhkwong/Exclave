#!/bin/bash

source "bin/init/env.sh"
source "bin/plugin/juicity/init.sh"

export CGO_LDFLAGS="-Wl,-z,max-page-size=16384"

DIR="$ROOT/x86"
mkdir -p $DIR
env CC=$ANDROID_X86_CC GOARCH=386 go build -v -o $DIR/$LIB_OUTPUT -buildvcs=false -trimpath -ldflags "-s -buildid=" ./cmd/client
