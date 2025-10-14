#!/bin/bash

# -buildvcs=false: github.com/sagernet/gomobile is used for reproducible build
CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -trimpath -buildvcs=false -ldflags='-s -buildid=' -tags='with_clash' . || exit 1
rm -r libcore-sources.jar

proj=../../app/libs
if [ -d $proj ]; then
  cp -f libcore.aar $proj
  echo ">> install $(realpath $proj)/libcore.aar"
fi
