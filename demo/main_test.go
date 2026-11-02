// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"strings"
	"testing"
)

func TestMessageEscapesTheProblemText(t *testing.T) {
	got := message("Sign-in failed", `access_denied: {"error":"x\"><script>alert(1)</script>"}`, "Start again")
	if strings.Contains(got, "<script>") || strings.Contains(got, `"><`) {
		t.Fatalf("problem text not escaped: %s", got)
	}
	for _, want := range []string{"<h1>Sign-in failed</h1>", `<p class="problem">access_denied: {&#34;error&#34;:`, `&lt;script&gt;`, `<p><a href="/">Start again</a></p>`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(message("Something went wrong", "boom", ""), "<a ") {
		t.Fatal("an empty link still drew a link")
	}
}
