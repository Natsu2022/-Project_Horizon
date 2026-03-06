package plugin

import (
	"crypto/sha1"
	"fmt"
)

func buildID(prefix, key string, index int) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%d", prefix, key, index)))
	return fmt.Sprintf("%s-%x", prefix, h[:4])
}
