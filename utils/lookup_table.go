package utils

// getBase32LookupTable 返回用于编码的 base32 查找表
func GetBase32LookupTable() []byte {
	return []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
}
