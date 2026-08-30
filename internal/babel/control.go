package babel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

const controlAPIVersion = 1
const maxControlFrame = 1 << 20

type controlHello struct {
	APIVersion    int      `json:"api_version"`
	ServerVersion string   `json:"server_version"`
	Capabilities  []string `json:"capabilities"`
}

type controlResponse struct {
	APIVersion int             `json:"api_version"`
	ID         uint64          `json:"id"`
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result"`
	Error      *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type daemonStatus struct {
	Ready              bool   `json:"ready"`
	Version            string `json:"version"`
	ConfigGeneration   uint64 `json:"config_generation"`
	ActiveConfigSHA256 string `json:"active_config_sha256"`
	AttachedInterfaces int    `json:"attached_interfaces"`
	Neighbors          int    `json:"neighbors"`
	SelectedRoutes     int    `json:"selected_routes"`
}

type reloadResult struct {
	ConfigGeneration   uint64 `json:"config_generation"`
	ActiveConfigSHA256 string `json:"active_config_sha256"`
}

func controlRequest(ctx context.Context, socket, command string, result any) error {
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = conn.SetDeadline(deadline)
	reader := bufio.NewReaderSize(conn, 64*1024)
	var hello controlHello
	if err := readControlJSON(reader, &hello); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if hello.APIVersion != controlAPIVersion {
		return fmt.Errorf("unsupported babel-rs control API %d", hello.APIVersion)
	}
	capable := false
	for _, capability := range hello.Capabilities {
		if capability == command {
			capable = true
			break
		}
	}
	if !capable {
		return fmt.Errorf("babel-rs %s does not advertise control command %q", hello.ServerVersion, command)
	}
	request := map[string]any{"api_version": controlAPIVersion, "id": uint64(1), "command": command, "params": map[string]any{}}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	var response controlResponse
	if err := readControlJSON(reader, &response); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if response.APIVersion != controlAPIVersion || response.ID != 1 {
		return errors.New("babel-rs returned a mismatched control response")
	}
	if !response.OK {
		if response.Error == nil {
			return errors.New("babel-rs rejected control request")
		}
		return fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
	}
	if result != nil && len(response.Result) != 0 {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return fmt.Errorf("decode result: %w", err)
		}
	}
	return nil
}

func readControlJSON(reader *bufio.Reader, value any) error {
	data, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(data) > maxControlFrame {
		return errors.New("control frame exceeds one MiB")
	}
	return json.Unmarshal(data, value)
}
