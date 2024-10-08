# Google Authenticator Go Package

## 简介

`googleAuthenticator` 是一个简单易用的 Go 包，用于生成 Google 身份验证器（2FA）所需的密钥和代码。它支持生成随机密钥、计算一次性密码（TOTP），并能生成对应的二维码以便于扫描。

## 安装

在您的 Go 项目中，使用以下命令获取该包：

```
go get github.com/suanju/googleAuthenticator
```

## 演示
```
package main

import (
	"fmt"
	"github.com/suanju/googleAuthenticator"
)

func main() {
	// 创建 GoogleAuthenticator 实例，传入 生成验证码的长度
	authenticator := googleAuthenticator.NewGoogleAuthenticator(6)

	// 创建一个 16 字节的随机密钥
	secret, err := authenticator.CreateSecret(16)
	if err != nil {
		fmt.Println("创建密钥时出错:", err)
		return
	}

	fmt.Println("生成的密钥:", secret)

	// 根据密钥获取当前验证码
	code, err := authenticator.GetCode(secret, 0)
	if err != nil {
		fmt.Println("生成验证码时出错:", err)
		return
	}

	fmt.Println("生成的验证码:", code)

	// 验证代码的有效性
	isValid := authenticator.VerifyCode(secret, code, 1, 0)
	fmt.Println("验证码是否有效?", isValid)

	// 生成二维码并输出 Base64 编码
	base64QRCode, err := authenticator.GenerateQRCode("MyAppName", secret)
	if err != nil {
		fmt.Println("生成二维码时出错:", err)
		return
	}

	fmt.Println("Base64 编码的二维码:", base64QRCode)
}

```
