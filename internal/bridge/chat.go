package bridge

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"devsecops-agent/internal/process"
)

const ChatProtocol = "devsec-chat/1"

type ChatEvent struct {
	Type string          `json:"type"`
	Seq  int             `json:"seq"`
	Raw  json.RawMessage `json:"-"`
}
type ChatMessage map[string]any

// ChatSession owns a dedicated host. Its queue has no lossy send path.
type ChatSession struct {
	cmd       *exec.Cmd
	input     io.WriteCloser
	writeMu   sync.Mutex
	mu        sync.Mutex
	err       error
	events    chan ChatEvent
	stop      chan struct{}
	wait      chan struct{}
	closeOnce sync.Once
}

func StartChat(python string, env []string) (*ChatSession, error) {
	module := os.Getenv("DEVSECOPS_CHAT_MODULE")
	if module == "" {
		module = "vulnscan.harness.rpc"
	}
	cmd := exec.Command(python, "-m", module)
	cmd.Env = env
	process.Configure(cmd)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	// The event stream is the only display boundary. Unstructured host stderr
	// cannot be assumed redacted and must not corrupt the terminal or echo keys.
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	s := &ChatSession{cmd: cmd, input: input, events: make(chan ChatEvent), stop: make(chan struct{}), wait: make(chan struct{})}
	incoming := make(chan ChatEvent)
	go s.queue(incoming)
	go func() {
		s.read(output, incoming)
		// Wait only after stdout is drained; Cmd.Wait closes its pipe.
		_ = cmd.Wait()
		close(s.wait)
	}()
	return s, nil
}

func (s *ChatSession) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

func (s *ChatSession) read(r io.Reader, incoming chan<- ChatEvent) {
	defer close(incoming)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxMessageBytes)
	for scanner.Scan() {
		var wire struct {
			Protocol string `json:"protocol"`
			ChatEvent
		}
		if err := json.Unmarshal(scanner.Bytes(), &wire); err != nil || wire.Protocol != ChatProtocol || wire.Type == "" || wire.Seq < 1 {
			s.setError(errors.New("invalid chat protocol response"))
			_ = s.input.Close()
			return
		}
		wire.Raw = append(json.RawMessage(nil), scanner.Bytes()...)
		select {
		case incoming <- wire.ChatEvent:
		case <-s.stop:
			return
		}
	}
	if scanner.Err() != nil {
		s.setError(errors.New("chat response exceeds limit or pipe failed"))
	} else {
		s.setError(errors.New("chat host disconnected; pending steps are undecided"))
	}
}

func (s *ChatSession) queue(in <-chan ChatEvent) {
	defer close(s.events)
	var pending []ChatEvent
	for in != nil || len(pending) > 0 {
		var out chan ChatEvent
		var first ChatEvent
		if len(pending) > 0 {
			out, first = s.events, pending[0]
		}
		select {
		case event, ok := <-in:
			if !ok {
				in = nil
			} else {
				pending = append(pending, event)
			}
		case out <- first:
			pending[0] = ChatEvent{}
			pending = pending[1:]
		case <-s.stop:
			return
		}
	}
}

func (s *ChatSession) Events() <-chan ChatEvent { return s.events }
func (s *ChatSession) Err() error               { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *ChatSession) Send(message ChatMessage) error {
	wire := make(ChatMessage, len(message)+1)
	for k, v := range message {
		wire[k] = v
	}
	wire["protocol"] = ChatProtocol
	data, err := json.Marshal(wire)
	if err != nil {
		return errors.New("invalid chat message")
	}
	if len(data)+1 > MaxMessageBytes {
		return errors.New("chat message exceeds protocol limit")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err = s.Err(); err != nil {
		return err
	}
	_, err = s.input.Write(append(data, '\n'))
	if err != nil {
		s.setError(errors.New("chat host disconnected"))
	}
	return err
}

func (s *ChatSession) Close() {
	s.closeOnce.Do(func() {
		s.setError(errors.New("chat session closed"))
		// Closing the pipe also unblocks a writer if the host stopped reading.
		_ = s.input.Close()
		select {
		case <-s.wait:
		case <-time.After(2 * time.Second):
			_ = process.KillTree(s.cmd)
			<-s.wait
		}
		close(s.stop)
	})
}
