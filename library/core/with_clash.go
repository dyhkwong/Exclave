//go:build with_clash

package libcore

import _ "libcore/clash"

func BuildWithClash() bool {
	return true
}
