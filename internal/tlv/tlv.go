package tlv

import (
	"encoding/binary"
	"errors"
)

var ErrMalformed = errors.New("malformed TLV body")

type View struct {
	Type   uint16
	Offset int
	Value  []byte
}

type Cursor struct {
	body []byte
	off  int
}

func NewCursor(body []byte) *Cursor { return &Cursor{body: body} }

// Next returns a borrowed view into the body supplied to NewCursor.
func (c *Cursor) Next() (View, bool, error) {
	if c.off == len(c.body) {
		return View{}, false, nil
	}
	if len(c.body)-c.off < 4 {
		return View{}, false, ErrMalformed
	}
	start := c.off
	typeCode := binary.BigEndian.Uint16(c.body[start : start+2])
	length := int(binary.BigEndian.Uint16(c.body[start+2 : start+4]))
	if length > len(c.body)-(start+4) {
		return View{}, false, ErrMalformed
	}
	c.off = start + 4 + length
	return View{Type: typeCode, Offset: start, Value: c.body[start+4 : c.off]}, true, nil
}

func Append(dst []byte, typeCode uint16, value []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start:start+2], typeCode)
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(value)))
	return append(dst, value...)
}
