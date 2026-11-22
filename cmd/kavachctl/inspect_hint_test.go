// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import "testing"

func TestConfigHintName(t *testing.T) {
	cases := [][3]string{
		{"/home/u/repo/.github/workflows/ci.yml", "ci.yml", ".github/workflows/ci.yml"},
		{".github/workflows/ci.yml", "ci.yml", ".github/workflows/ci.yml"},
		{"/home/u/repo/sshd_config", "sshd_config", "sshd_config"},
		{"x.github/workflows/ci.yml", "ci.yml", "ci.yml"},
	}
	for _, c := range cases {
		if got := configHintName(c[0], c[1]); got != c[2] {
			t.Errorf("%s: got %q want %q", c[0], got, c[2])
		}
	}
}
