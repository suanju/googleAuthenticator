package utils

import (
	"encoding/base32"
	"strings"
)

// base32Decode 解码一个 base32 编码的字符串
func Base32Decode(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimRight(secret, "="))
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
