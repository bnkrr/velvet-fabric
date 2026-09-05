package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/linejson"
)

const APIVersion = 1
const maxFrame = 1 << 20

type Handlers struct {
	Status   func() any
	Reload   func(context.Context) error
	Shutdown func()
}

type request struct {
	APIVersion int             `json:"api_version"`
	ID         uint64          `json:"id"`
	Command    string          `json:"command"`
	Params     json.RawMessage `json:"params"`
}

type response struct {
	APIVersion int        `json:"api_version"`
	ID         uint64     `json:"id"`
	OK         bool       `json:"ok"`
	Result     any        `json:"result,omitempty"`
	Error      *errorBody `json:"error,omitempty"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Serve(ctx context.Context, path, version string, handlers Handlers) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket control path %s", path)
		}
		probe, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return fmt.Errorf("control socket %s is already active", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(conn, version, handlers)
	}
}

func handle(conn net.Conn, version string, handlers Handlers) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSON(conn, map[string]any{"type": "hello", "api_version": APIVersion, "server_version": version, "capabilities": []string{"status", "reload", "shutdown"}}); err != nil {
		return
	}
	reader := bufio.NewReaderSize(conn, 64*1024)
	for {
		var req request
		if err := readJSON(reader, &req); err != nil {
			return
		}
		resp := response{APIVersion: APIVersion, ID: req.ID}
		if req.APIVersion != APIVersion {
			resp.Error = &errorBody{Code: "unsupported_version", Message: fmt.Sprintf("expected API version %d", APIVersion)}
		} else {
			switch req.Command {
			case "status":
				resp.OK, resp.Result = true, handlers.Status()
			case "reload":
				reloadContext, cancel := context.WithTimeout(context.Background(), 75*time.Second)
				err := handlers.Reload(reloadContext)
				cancel()
				if err != nil {
					resp.Error = &errorBody{Code: "reload_rejected", Message: err.Error()}
				} else {
					resp.OK, resp.Result = true, map[string]bool{"committed": true}
				}
			case "shutdown":
				resp.OK, resp.Result = true, map[string]bool{"accepted": true}
			default:
				resp.Error = &errorBody{Code: "unknown_command", Message: fmt.Sprintf("unknown command %q", req.Command)}
			}
		}
		if err := writeJSON(conn, resp); err != nil {
			return
		}
		if req.Command == "shutdown" && resp.OK {
			handlers.Shutdown()
			return
		}
	}
}

func Request(ctx context.Context, path, command string, result any) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 64*1024)
	var hello struct {
		APIVersion int `json:"api_version"`
	}
	if err := readJSON(reader, &hello); err != nil {
		return err
	}
	if hello.APIVersion != APIVersion {
		return fmt.Errorf("unsupported control API %d", hello.APIVersion)
	}
	if err := writeJSON(conn, map[string]any{"api_version": APIVersion, "id": uint64(1), "command": command, "params": map[string]any{}}); err != nil {
		return err
	}
	var resp struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *errorBody      `json:"error"`
	}
	if err := readJSON(reader, &resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == nil {
			return errors.New("control command rejected")
		}
		return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}
	if result != nil {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}

func readJSON(reader *bufio.Reader, value any) error {
	return linejson.Read(reader, maxFrame, value)
}

func writeJSON(writer net.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = writer.Write(data)
	return err
}
