package utils

// timingSafeEquals 安全地比较两个字符串
func TimingSafeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}
