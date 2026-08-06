// Command schlock-parse reads a bash script on stdin and writes its
// typed-JSON AST (mvdan.cc/sh/v3 syntax + syntax/typedjson) to stdout.
// No flags, no network, no filesystem writes.
//
// Exit-code contract (consumed by schlock's NativeBridge, spec §3.1):
//
//	0  parsed; JSON AST on stdout
//	2  parse error; message on stderr
//	3  stdin read error; message on stderr
//	4  stdout encode/write error; message on stderr
//	>4 reserved
//
// A stdin read error must never be swallowed: parsing the prefix of a
// short read would drop a trailing `; rm -rf /` and under-block.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"mvdan.cc/sh/v3/syntax"
	"mvdan.cc/sh/v3/syntax/typedjson"
)

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	src, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	// Default parser: bash dialect, comments off (no schlock rule inspects them).
	f, err := syntax.NewParser().Parse(bytes.NewReader(src), "")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := typedjson.Encode(stdout, f); err != nil {
		fmt.Fprintln(stderr, err)
		return 4
	}
	return 0
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}
