/*
Copyright (C) 2025 by dyhkwong

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

import (
	"os"
	_ "unsafe"
)

// Workaround "seccomp prevented call to disallowed arm64 system call 434" crash on Android < 12.
// https://github.com/golang/go/issues/70508
// API level 26 and 27 say "disallowed arm64 system call 0" instead of 434.
// https://github.com/python/cpython/issues/123014

//go:linkname checkPidfdOnce os.checkPidfdOnce
var checkPidfdOnce func() error

func init() {
	checkPidfdOnce = func() error {
		return os.ErrInvalid
	}
}
