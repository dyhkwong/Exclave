/*
Copyright (c) 2015-2022 V2Fly Community
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
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

// https://github.com/SagerNet/v2ray-core/blob/26e36b1cb46f387cacd65c1a5900be592913f842/common/cond.go#L17-L42

package libcore

func Contains[T comparable](arr []T, target T) bool {
	for i := range arr {
		if target == arr[i] {
			return true
		}
	}
	return false
}

func Map[T any, N any](arr []T, block func(it T) N) []N {
	var retArr []N
	for index := range arr {
		retArr = append(retArr, block(arr[index]))
	}
	return retArr
}

func Filter[T any](arr []T, block func(it T) bool) []T {
	var retArr []T
	for _, it := range arr {
		if block(it) {
			retArr = append(retArr, it)
		}
	}
	return retArr
}
