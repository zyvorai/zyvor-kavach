// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDocsIndexListsEveryDoc fails when a documentation file under docs/ is linked from neither
// docs/index.md nor docs/README.md, so a new doc cannot ship unreachable.
func TestDocsIndexListsEveryDoc(t *testing.T) {
	root := filepath.Join("..", "..", "docs")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	linked := read("index.md") + "\n" + read("README.md")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(p)
		if ext != ".md" && ext != ".yaml" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "index.md" {
			return nil
		}
		if !strings.Contains(linked, "("+rel+")") && !strings.Contains(linked, "/docs/"+rel+")") {
			t.Errorf("docs/%s is not linked from docs/index.md or docs/README.md", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDocsConsoleListsMenuPages fails when a console Browse-menu page is missing from docs/console.md.
func TestDocsConsoleListsMenuPages(t *testing.T) {
	html, err := os.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "console.md"))
	if err != nil {
		t.Fatal(err)
	}
	labels := regexp.MustCompile(`data-page="[a-z-]+" role="menuitem">([^<]+)`).FindAllStringSubmatch(string(html), -1)
	if len(labels) < 40 {
		t.Fatalf("found only %d menu pages in dashboard.html; pattern stale?", len(labels))
	}
	for _, m := range labels {
		if !strings.Contains(string(doc), strings.TrimSpace(m[1])) {
			t.Errorf("console menu page %q is not listed in docs/console.md", m[1])
		}
	}
}
