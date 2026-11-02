package bridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("GO_CHAT_HELPER"); mode != "" {
		switch mode {
		case "burst", "exit":
			n := 10000
			if mode == "exit" {
				n = 3
			}
			for i := 1; i <= n; i++ {
				fmt.Printf("{\"protocol\":\"devsec-chat/1\",\"type\":\"text_delta\",\"seq\":%d}\n", i)
			}
		case "echo":
			s := bufio.NewScanner(os.Stdin)
			if s.Scan() {
				fmt.Println(s.Text())
			}
		case "bad":
			fmt.Println(`{"protocol":"wrong","type":"ready","seq":1}`)
		case "large":
			fmt.Println(strings.Repeat("x", 8*1024*1024+1))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperChat(t *testing.T, mode string) *ChatSession {
	t.Helper()
	s, err := StartChat(os.Args[0], append(os.Environ(), "GO_CHAT_HELPER="+mode))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestChatEventsNeverDropUnderBurst(t *testing.T) {
	s := helperChat(t, "burst")
	i := 0
	for event := range s.Events() {
		i++
		if event.Seq != i {
			t.Fatalf("seq=%d want=%d", event.Seq, i)
		}
		if i%100 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if i != 10000 {
		t.Fatalf("received %d events: %v", i, s.Err())
	}
}

func TestChatSendAddsProtocol(t *testing.T) {
	s := helperChat(t, "echo")
	msg := ChatMessage{"type": "hello", "seq": 1}
	if err := s.Send(msg); err != nil {
		t.Fatal(err)
	}
	e := <-s.Events()
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["protocol"] != "devsec-chat/1" {
		t.Fatal("missing protocol")
	}
	if _, ok := msg["protocol"]; ok {
		t.Fatal("Send mutated caller message")
	}
}

func TestChatBrokenPipeClosesEventsWithError(t *testing.T) {
	s := helperChat(t, "exit")
	n := 0
	for range s.Events() {
		n++
	}
	if n != 3 || s.Err() == nil {
		t.Fatalf("events=%d err=%v", n, s.Err())
	}
}

func TestChatMalformedAndOversizedLinesBreakSession(t *testing.T) {
	for _, mode := range []string{"bad", "large"} {
		t.Run(mode, func(t *testing.T) {
			s := helperChat(t, mode)
			for range s.Events() {
				t.Fatal("invalid event delivered")
			}
			if s.Err() == nil {
				t.Fatal("missing protocol error")
			}
		})
	}
}

func TestChatCloseWithoutEventConsumer(t *testing.T) {
	s := helperChat(t, "burst")
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on consumer")
	}
}
