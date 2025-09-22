//go:build android

/*
Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package libcore

/*
   #cgo LDFLAGS: -landroid -llog

   #include <android/log.h>
   #include <string.h>
   #include <stdlib.h>
*/
import "C"

import (
	"log"
	"strings"
	"unsafe"

	appLog "github.com/v2fly/v2ray-core/v5/app/log"
	commonLog "github.com/v2fly/v2ray-core/v5/common/log"
)

var (
	tag      = C.CString("libcore")
	tagV2Ray = C.CString("v2ray-core")
)

type v2rayLogWriter struct{}

func (w *v2rayLogWriter) Write(s string) error {
	var priority C.int
	if strings.Contains(s, "[Debug]") {
		s = strings.Replace(s, "[Debug]", "", 1)
		priority = C.ANDROID_LOG_DEBUG
	} else if strings.Contains(s, "[Info]") {
		s = strings.Replace(s, "[Info]", "", 1)
		priority = C.ANDROID_LOG_INFO
	} else if strings.Contains(s, "[Warning]") {
		s = strings.Replace(s, "[Warning]", "", 1)
		priority = C.ANDROID_LOG_WARN
	} else if strings.Contains(s, "[Error]") {
		s = strings.Replace(s, "[Error]", "", 1)
		priority = C.ANDROID_LOG_ERROR
	} else {
		priority = C.ANDROID_LOG_DEBUG
	}

	str := C.CString(strings.TrimSpace(s))
	C.__android_log_write(priority, tagV2Ray, str)
	C.free(unsafe.Pointer(str))
	return nil
}

func (w *v2rayLogWriter) Close() error {
	return nil
}

type stdLogWriter struct{}

func (stdLogWriter) Write(p []byte) (n int, err error) {
	str := C.CString(string(p))
	C.__android_log_write(C.ANDROID_LOG_INFO, tag, str)
	C.free(unsafe.Pointer(str))
	return len(p), nil
}

func init() {
	log.SetOutput(stdLogWriter{})
	log.SetFlags(log.Flags() &^ log.LstdFlags)

	_ = appLog.RegisterHandlerCreator(appLog.LogType_Console, func(lt appLog.LogType,
		options appLog.HandlerCreatorOptions,
	) (commonLog.Handler, error) {
		return commonLog.NewLogger(func() commonLog.Writer {
			return &v2rayLogWriter{}
		}), nil
	})
}
