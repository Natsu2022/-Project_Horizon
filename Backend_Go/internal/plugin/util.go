package plugin

import (
	"crypto/sha1"
	"fmt"
)

// buildID generates a short deterministic ID for a Finding.
// Format: "PREFIX-XXXXXXXX"  (PREFIX = e.g. "HDR", "SQL", "XSS"; X = 4-byte SHA1 hex)
// Example: HDR-1a2b3c4d
//
// The hash input is "PREFIX|URL|index", ensuring each finding at the same URL
// gets a unique ID even when multiple findings share the same plugin and URL.
// Called by every plugin after constructing its findings slice.
func buildID(prefix, key string, index int) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%d", prefix, key, index)))
	return fmt.Sprintf("%s-%x", prefix, h[:4])
}
