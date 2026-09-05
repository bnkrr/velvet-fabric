package linejson

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadAcrossBufferBoundaries(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(`{"value":"abcdefgh"}`+"\n"), 4)
	var value struct {
		Value string `json:"value"`
	}
	if err := Read(reader, 64, &value); err != nil {
		t.Fatal(err)
	}
	if value.Value != "abcdefgh" {
		t.Fatalf("decoded value %q", value.Value)
	}
}

func TestReadRejectsOversizeLine(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 100)+"\n"), 8)
	var value any
	err := Read(reader, 16, &value)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v, want size error", err)
	}
}

func TestReadRequiresNewline(t *testing.T) {
	var value any
	err := Read(bufio.NewReader(strings.NewReader(`{}`)), 16, &value)
	if err == nil {
		t.Fatal("unterminated frame was accepted")
	}
}
