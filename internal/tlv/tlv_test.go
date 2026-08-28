package tlv

import (
	"bytes"
	"testing"
)

func TestCursorReturnsBorrowedViewsAndBoundsChecks(t *testing.T) {
	body := Append(nil, 7, []byte{1, 2, 3})
	view, ok, err := NewCursor(body).Next()
	if err != nil || !ok || view.Type != 7 || !bytes.Equal(view.Value, []byte{1, 2, 3}) {
		t.Fatalf("unexpected view: %#v %v", view, err)
	}
	view.Value[0] = 9
	if body[4] != 9 {
		t.Fatal("view did not borrow frame storage")
	}
	if _, _, err := NewCursor([]byte{0, 1, 0, 2, 9}).Next(); err == nil {
		t.Fatal("truncated value was accepted")
	}
}
