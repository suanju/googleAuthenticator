package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"math"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/suanju/googleAuthenticator/utils"
)

type GoogleAuthenticator struct {
	codeLength int
}

// NewGoogleAuthenticator 创建一个新的 GoogleAuthenticator 实例
func NewGoogleAuthenticator(codeLength int) *GoogleAuthenticator {
	return &GoogleAuthenticator{
		codeLength: codeLength,
	}
}

// CreateSecret 生成指定长度的新密钥
func (ga *GoogleAuthenticator) CreateSecret(secretLength int) (string, error) {
	if secretLength < 16 || secretLength > 128 {
		return "", errors.New("bad secret length")
	}

	validChars := utils.GetBase32LookupTable()
	secret := make([]byte, secretLength)

	_, err := rand.Read(secret)
	if err != nil {
		return "", errors.New("no source of secure random")
	}

	var result strings.Builder
	for _, b := range secret {
		result.WriteByte(validChars[int(b)&31])
	}

	return result.String(), nil
}

// GetCode 计算给定密钥和时间片的 TOTP 代码
func (ga *GoogleAuthenticator) GetCode(secret string, timeSlice int64) (string, error) {
	if timeSlice == 0 {
		timeSlice = time.Now().Unix() / 30
	}

	secretKey, err := utils.Base32Decode(secret)
	if err != nil {
		return "", err
	}

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeSlice))

	hash := hmac.New(sha1.New, secretKey)
	hash.Write(timeBytes)
	hmacHash := hash.Sum(nil)

	offset := hmacHash[len(hmacHash)-1] & 0x0F
	value := int32(binary.BigEndian.Uint32(hmacHash[offset:offset+4]) & 0x7FFFFFFF)

	modulo := int32(math.Pow10(ga.codeLength))
	return fmt.Sprintf("%06d", value%modulo), nil
}

// VerifyCode 检查给定的代码是否对提供的密钥和误差范围有效
func (ga *GoogleAuthenticator) VerifyCode(secret string, code string, discrepancy int, currentTimeSlice int64) bool {
	if len(code) != 6 {
		return false
	}

	if currentTimeSlice == 0 {
		currentTimeSlice = time.Now().Unix() / 30
	}

	for i := -discrepancy; i <= discrepancy; i++ {
		calculatedCode, err := ga.GetCode(secret, currentTimeSlice+int64(i))
		if err != nil {
			continue
		}
		if utils.TimingSafeEquals(calculatedCode, code) {
			return true
		}
	}

	return false
}

// GenerateQRCode 生成二维码并返回其 Base64 编码
func (ga *GoogleAuthenticator) GenerateQRCode(title string, secret string) (string, error) {
	// 生成二维码内容
	qrContent := fmt.Sprintf("otpauth://totp/%s?secret=%s", title, secret)

	qrCode, err := qr.Encode(qrContent, qr.L, qr.Auto)
	if err != nil {
		return "", err
	}

	qrCode, err = barcode.Scale(qrCode, 250, 250)
	if err != nil {
		return "", err
	}

	var pngData strings.Builder
	if err := png.Encode(&pngData, qrCode); err != nil {
		return "", err
	}

	base64QR := base64.StdEncoding.EncodeToString([]byte(pngData.String()))

	return base64QR, nil
}

func main() {
	authenticator := NewGoogleAuthenticator(6)
	secret, err := authenticator.CreateSecret(16)
	if err != nil {
		fmt.Println("Error creating secret:", err)
		return
	}

	fmt.Println("Generated Secret:", secret)

	code, err := authenticator.GetCode(secret, 0)
	if err != nil {
		fmt.Println("Error generating code:", err)
		return
	}

	fmt.Println("Generated Code:", code)

	isValid := authenticator.VerifyCode(secret, code, 1, 0)
	fmt.Println("Is the code valid?", isValid)

	// 生成二维码并输出 Base64 编码
	base64QRCode, err := authenticator.GenerateQRCode("MyAppName", secret)
	if err != nil {
		fmt.Println("Error generating QR code:", err)
		return
	}

	fmt.Println("Base64 QR Code:", base64QRCode)
}
