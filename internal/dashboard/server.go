// Package dashboard preserves local dashboard routes and escaped templates.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"devsecops-agent/internal/service"
)

type Server struct {
	Backend *service.Backend
	Output  string
}
type csrfKey struct{}

func LocalHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.Backend.History(r.Context())
		if err != nil {
			s.failure(w, err)
			return
		}
		s.render(w, r, "targets.html", map[string]any{"runs": rows})
	})
	mux.HandleFunc("POST /scans", func(w http.ResponseWriter, r *http.Request) {
		cfg := service.Defaults()
		cfg.OutputDir = s.Output
		checkout := r.FormValue("repository_checkout_path")
		if checkout == "" {
			checkout = "."
		}
		result, err := s.Backend.Run(r.Context(), map[string]any{"checkout": checkout, "repo": r.FormValue("target_repository_url"), "commit": r.FormValue("target_commit_sha"), "configuration": cfg}, nil)
		if err != nil {
			s.failure(w, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/runs/%v", result["id"]), http.StatusSeeOther)
	})
	mux.HandleFunc("GET /runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		data, err := s.Backend.Store.RunContext(r.Context(), r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s.render(w, r, "runs.html", data)
	})
	mux.HandleFunc("GET /runs/{id}/findings", func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		if raw := r.URL.Query().Get("offset"); raw != "" {
			var err error
			offset, err = strconv.Atoi(raw)
			if err != nil || offset < 0 {
				http.Error(w, "Invalid page", 400)
				return
			}
		}
		data, err := s.Backend.Store.FindingsContext(r.Context(), r.PathValue("id"), r.URL.Query().Get("query"), offset)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s.render(w, r, "findings.html", data)
	})
	mux.HandleFunc("GET /runs/{id}/findings/{finding}", func(w http.ResponseWriter, r *http.Request) {
		s.evidence(w, r, r.PathValue("id"), r.PathValue("finding"))
	})
	mux.HandleFunc("GET /findings/{finding}", func(w http.ResponseWriter, r *http.Request) {
		pk, _, err := s.Backend.Store.FindAny(r.Context(), r.PathValue("finding"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s.evidence(w, r, strconv.Itoa(pk), r.PathValue("finding"))
	})
	mux.HandleFunc("POST /findings/{finding}/status", func(w http.ResponseWriter, r *http.Request) {
		id := r.FormValue("run_id")
		scoped := id != ""
		if id == "" {
			pk, _, err := s.Backend.Store.FindAny(r.Context(), r.PathValue("finding"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			id = strconv.Itoa(pk)
		}
		if err := s.Backend.Store.SetStatus(r.Context(), id, r.PathValue("finding"), r.FormValue("status")); err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		destination := "/findings/" + r.PathValue("finding")
		if scoped {
			destination = "/runs/" + id + destination
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
	})
	mux.HandleFunc("GET /runs/{id}/export/{format}", func(w http.ResponseWriter, r *http.Request) {
		format := r.PathValue("format")
		mime := map[string]string{"json": "application/json", "sarif": "application/sarif+json", "html": "text/html", "markdown": "text/markdown"}[format]
		if mime == "" {
			http.Error(w, "Unsupported export", 422)
			return
		}
		path, err := s.Backend.Export(r.Context(), r.PathValue("id"), format, s.Output)
		if err != nil {
			s.failure(w, err)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			s.failure(w, err)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /api/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		info, err := s.Backend.Store.Summary(r.Context(), r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		counts, err := s.Backend.Store.Counts(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failure(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": info.ID, "status": info.Status, "counts": counts})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		if cookie, err := r.Cookie("vulnscan_csrf"); err == nil {
			token = cookie.Value
		}
		if token == "" {
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				s.failure(w, err)
				return
			}
			token = base64.RawURLEncoding.EncodeToString(random[:])
		}
		http.SetCookie(w, &http.Cookie{Name: "vulnscan_csrf", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid form", 400)
				return
			}
			supplied := r.Header.Get("X-CSRF-Token")
			if supplied == "" {
				supplied = r.FormValue("_csrf")
			}
			if subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), csrfKey{}, token)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	data["csrf_token"] = r.Context().Value(csrfKey{})
	var html string
	if err := s.Backend.Client.Call(r.Context(), "render_page", map[string]any{"template": name, "context": data}, &html, nil); err != nil {
		s.failure(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, html)
}
func (s *Server) evidence(w http.ResponseWriter, r *http.Request, id, fid string) {
	raw, err := s.Backend.Finding(r.Context(), id, fid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var finding map[string]any
	if err = json.Unmarshal(raw, &finding); err != nil {
		s.failure(w, err)
		return
	}
	s.render(w, r, "evidence.html", map[string]any{"finding": finding, "run_id": id})
}
func (s *Server) failure(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
func (s *Server) Serve(ctx context.Context, host string, port int) error {
	if !LocalHost(host) {
		return fmt.Errorf("dashboard must bind to localhost")
	}
	server := &http.Server{Addr: net.JoinHostPort(host, strconv.Itoa(port)), Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
