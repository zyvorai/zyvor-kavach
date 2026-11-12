// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	zyvorOrange = "\033[38;2;241;90;41m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiCyan    = "\033[36m"
	ansiGreen   = "\033[32m"
	resetColor  = "\033[0m"
)

func useColor(w *os.File) bool {
	if w == nil {
		w = os.Stdout
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if v := strings.TrimSpace(os.Getenv("KAVACH_CLI_COLOR")); v != "" {
		return !strings.EqualFold(v, "false") && v != "0"
	}
	return isTTY(w)
}

func colorize(w *os.File, code, s string) string {
	if !useColor(w) {
		return s
	}
	return code + s + resetColor
}

func printBanner(w *os.File) {
	if w == nil {
		w = os.Stdout
	}
	logo := []string{
		` _  __                      _     `,
		`| |/ /__ ___ ____ _ ____ __| |_  `,
		`| ' </ _' \ V / _' / _/ _ \ ' \ `,
		`|_|\_\__,_|\_/\__,_\__\___/_||_|`,
	}
	title := "  Kavach · Zyvor"
	tag := "  observe · detect · report · never contain"
	if useColor(w) {
		fmt.Fprint(w, zyvorOrange)
	}
	for _, line := range logo {
		fmt.Fprintln(w, line)
	}
	if useColor(w) {
		fmt.Fprint(w, resetColor)
	}
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, tag)
	fmt.Fprintln(w)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func bannerEnabled() bool {
	return os.Getenv("KAVACH_CLI_NO_BANNER") == ""
}

func maybeBanner() {
	if bannerEnabled() && isTTY(os.Stdout) {
		printBanner(os.Stdout)
	}
}
