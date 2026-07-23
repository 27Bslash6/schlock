package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("simulated stdin failure") }

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("simulated stdout failure") }

// Exit-code contract (spec §3.1): 0 parsed, 2 parse error, 3 stdin read
// error, 4 encode/write error. 3 exists so a short read can never be
// mistaken for a clean prefix parse (spec §11 finding 10).
func TestExitContract(t *testing.T) {
	t.Run("success emits JSON on stdout, exit 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := run(strings.NewReader("echo hi"), &stdout, &stderr); got != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", got, stderr.String())
		}
		if !json.Valid(stdout.Bytes()) {
			t.Fatalf("stdout is not valid JSON: %q", stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr not empty on success: %q", stderr.String())
		}
	})

	t.Run("parse error exits 2 with stderr message", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := run(strings.NewReader("echo $("), &stdout, &stderr); got != 2 {
			t.Fatalf("exit = %d, want 2", got)
		}
		if stderr.Len() == 0 {
			t.Fatal("parse error must write a message to stderr")
		}
		if stdout.Len() != 0 {
			t.Fatalf("no JSON may be emitted on parse error, got %q", stdout.String())
		}
	})

	t.Run("stdin read error exits 3, never a prefix parse", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := run(failReader{}, &stdout, &stderr); got != 3 {
			t.Fatalf("exit = %d, want 3", got)
		}
		if stderr.Len() == 0 {
			t.Fatal("stdin read error must write a message to stderr")
		}
		if stdout.Len() != 0 {
			t.Fatalf("no JSON may be emitted on stdin read error, got %q", stdout.String())
		}
	})

	t.Run("stdout write error exits 4", func(t *testing.T) {
		var stderr bytes.Buffer
		if got := run(strings.NewReader("echo hi"), failWriter{}, &stderr); got != 4 {
			t.Fatalf("exit = %d, want 4", got)
		}
		if stderr.Len() == 0 {
			t.Fatal("write error must write a message to stderr")
		}
	})
}

// The 24-construct eval corpus (spec §1/§2), including the 7 constructs
// bashlex fails on. Every entry must parse cleanly to typed JSON.
func TestCorpusParses(t *testing.T) {
	raw, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Name         string `json:"name"`
		Script       string `json:"script"`
		BashlexFails bool   `json:"bashlex_fails"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) != 24 {
		t.Fatalf("corpus has %d constructs, want 24", len(corpus))
	}
	bashlexFailing := 0
	for _, c := range corpus {
		if c.BashlexFails {
			bashlexFailing++
		}
		t.Run(c.Name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(strings.NewReader(c.Script), &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", got, stderr.String())
			}
			if !json.Valid(stdout.Bytes()) {
				t.Fatal("stdout is not valid JSON")
			}
		})
	}
	if bashlexFailing != 7 {
		t.Fatalf("corpus marks %d bashlex-failing constructs, want 7", bashlexFailing)
	}
}
