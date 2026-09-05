package linejson

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
)

// Read decodes one newline-delimited JSON value without buffering more than
// max bytes. The newline counts toward the limit.
func Read(reader *bufio.Reader, max int, value any) error {
	if max < 1 {
		return errors.New("line JSON limit must be positive")
	}
	data := make([]byte, 0, min(max, reader.Size()))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > max-len(data) {
			return fmt.Errorf("line JSON frame exceeds %d bytes", max)
		}
		data = append(data, fragment...)
		switch {
		case err == nil:
			return json.Unmarshal(data, value)
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return err
		}
	}
}
