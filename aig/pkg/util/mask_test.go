package util

import "testing"

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"len 1", "a", "****"},
		{"len 4", "abcd", "****"},
		{"len 5", "abcde", "a***e"},
		{"len 8", "abcdefgh", "a******h"},
		{"len 9", "abcdefghi", "abcd***hi"},
		{"len long", "sk-1234567890abcdef", "sk-1*************ef"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaskSecret(c.in)
			if got != c.want {
				t.Errorf("MaskSecret(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
