package subscription

import (
	"bytes"
	"encoding/base64"
)

// Decode tries the base64 variants a subscription body is commonly
// encoded with (standard and URL-safe alphabets, each padded and
// unpadded) and falls back to treating the body as already-plaintext if
// none of them decode without error. In practice this is unambiguous: a
// genuine plaintext vless:// list contains characters (':', '?', '&',
// '@', ...) outside the base64 alphabet, so it reliably fails every
// attempt and falls through correctly.
func Decode(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)

	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(string(trimmed)); err == nil {
			return decoded
		}
	}
	return body
}
