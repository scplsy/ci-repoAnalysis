// Package util 提供本工具内部使用的辅助函数。
//
// SDK 已经提供了基础的日志输出（util.Info/Warn/Error），
// 这里只补充 modelToken 等敏感凭据脱敏的工具方法。
package util

// MaskSecret 对秘钥/Token 类字符串进行脱敏，避免在日志中明文打印。
//
// 规则：
//   - 长度 == 0，返回空串
//   - 长度 <= 4，返回 "****"
//   - 长度 5~8，保留首尾各 1 个字符，中间用 * 填充
//   - 长度 > 8，保留首 4 个字符 + 末 2 个字符，中间用 * 填充
//
// 示例：
//
//	MaskSecret("")                     // ""
//	MaskSecret("ab")                   // "****"
//	MaskSecret("abcdef")               // "a****f"
//	MaskSecret("sk-xxxxxxxxxxxxxxxx")  // "sk-x*************xx"
func MaskSecret(s string) string {
	n := len(s)
	if n == 0 {
		return ""
	}
	if n <= 4 {
		return "****"
	}
	if n <= 8 {
		return s[:1] + repeatStar(n-2) + s[n-1:]
	}
	return s[:4] + repeatStar(n-6) + s[n-2:]
}

func repeatStar(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = '*'
	}
	return string(b)
}
