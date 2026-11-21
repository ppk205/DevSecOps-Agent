package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"encoding/xml"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
)

type Message struct {
	Text string
}

func handler(db DB, w http.ResponseWriter, r *http.Request) {
	uname := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = 'static'")
	_ = rows

	out, _ := exec.Command("ls", "-l").CombinedOutput()
	_ = out

	staticPage, _ := os.ReadFile("/var/www/index.html")
	_ = staticPage

	resp, _ := http.Get("https://status.internal/health")
	_ = resp

	http.Redirect(w, r, "/home", http.StatusFound)

	t, _ := template.New("p").Parse("<h1>hi</h1>")
	_ = t

	sum := sha256.Sum256([]byte("pw"))
	_ = sum

	buf := make([]byte, 16)
	_, _ = rand.Read(buf)

	cfg := &tls.Config{InsecureSkipVerify: false}
	_ = cfg

	payload := []byte("static")
	dec := gob.NewDecoder(bytes.NewReader(payload))
	var m Message
	_ = dec.Decode(&m)

	var v Message
	_ = xml.Unmarshal([]byte("<root/>"), &v)

	log.Printf("startup on %s", ":8080")


	w.Write([]byte(template.HTMLEscapeString(uname)))
}
