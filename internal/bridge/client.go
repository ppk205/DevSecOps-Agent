// Package bridge owns the Python service during migration. Closing stdin
// requests cooperative cancellation and evidence persistence before shutdown.
package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"devsecops-agent/internal/process"
)

const Version = 1
const MaxMessageBytes = 8 * 1024 * 1024

type Event struct {
	RunID     string `json:"run_id"`
	PK        int    `json:"pk"`
	Stage     string `json:"stage"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Sequence  int    `json:"sequence"`
}
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result"`
	Event   Event           `json:"event"`
	Error   struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
type Client struct {
	cmd       *exec.Cmd
	input     io.WriteCloser
	writeMu   sync.Mutex
	mu        sync.Mutex
	pending   map[string]chan Response
	next      atomic.Uint64
	done      chan struct{}
	err       error
	wait      chan error
	closeOnce sync.Once
}

func Start(python, db string) (*Client, error) {
	return StartWithEnvironment(python, db, nil)
}

// StartWithEnvironment gives the service the same import environment as the
// Python CLI. A nil environment retains the caller's environment, as Start does.
func StartWithEnvironment(python, db string, env []string) (*Client, error) {
	module := os.Getenv("DEVSECOPS_RPC_MODULE")
	if module == "" {
		module = "vulnscan.core.rpc"
	}
	cmd := exec.Command(python, "-m", module, "--db-path", db)
	cmd.Env = env
	process.Configure(cmd)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{cmd: cmd, input: input, pending: make(map[string]chan Response), done: make(chan struct{}), wait: make(chan error, 1)}
	go c.read(output)
	go func() { c.wait <- cmd.Wait() }()
	return c, nil
}

func (c *Client) read(output io.Reader) {
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 64*1024), MaxMessageBytes)
	for scanner.Scan() {
		var response Response
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil || response.Version != Version {
			c.mu.Lock()
			c.err = errors.New("invalid service protocol response")
			c.mu.Unlock()
			break
		}
		c.mu.Lock()
		ch := c.pending[response.ID]
		c.mu.Unlock()
		if ch != nil {
			if response.Kind == "event" {
				select {
				case ch <- response:
				default:
				}
			} else {
				ch <- response
			}
		}
	}
	c.mu.Lock()
	if c.err == nil {
		c.err = scanner.Err()
		if c.err == nil {
			c.err = errors.New("application worker exited")
		}
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *Client) write(id, method string, params any) error {
	data, err := json.Marshal(map[string]any{"version": Version, "id": id, "method": method, "params": params})
	if err != nil {
		return err
	}
	if len(data)+1 > MaxMessageBytes {
		return errors.New("request exceeds protocol limit")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.input.Write(append(data, '\n'))
	return err
}

func (c *Client) Call(ctx context.Context, method string, params any, target any, event func(Event)) error {
	id := strconv.FormatUint(c.next.Add(1), 10)
	ch := make(chan Response, 256)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	if err := c.write(id, method, params); err != nil {
		return err
	}
	for {
		select {
		case response := <-ch:
			if response.Kind == "event" {
				if event != nil {
					event(response.Event)
				}
				continue
			}
			if !response.OK {
				return fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
			}
			if target != nil {
				return json.Unmarshal(response.Result, target)
			}
			return nil
		case <-ctx.Done():
			// Signal the owned service even when intake has not allocated a run yet.
			_ = c.write("cancel-"+id, "cancel_request", map[string]string{"request_id": id})
			return ctx.Err()
		case <-c.done:
			c.mu.Lock()
			err := c.err
			c.mu.Unlock()
			return err
		}
	}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		_ = c.input.Close()
		c.writeMu.Unlock()
		select {
		case <-c.wait:
		case <-time.After(15 * time.Second):
			_ = process.KillTree(c.cmd)
			<-c.wait
		}
	})
}
