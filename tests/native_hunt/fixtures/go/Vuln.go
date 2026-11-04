//go:build ignore

package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"text/template"
)

type Message struct {
	Text string
}

func handler(db DB, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
	_ = rows

	tool := r.URL.Query().Get("tool")
	out, _ := exec.Command("sh", "-c", tool).CombinedOutput()
	fmt.Println(string(out))

	name := r.URL.Query().Get("n")
	w.Write([]byte("hello " + name))

	f := r.URL.Query().Get("f")
	data, _ := os.ReadFile("/var/www/" + f)
	_ = data

	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	_ = resp

	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)

	title := r.URL.Query().Get("title")
	tpl := "<h1>" + title + "</h1>"
	t, _ := template.New("p").Parse(tpl)
	_ = t

	pw := r.FormValue("pw")
	h := md5.New()
	h.Write([]byte(pw))

	code := rand.Intn(1000000)
	_ = code

	cfg := &tls.Config{InsecureSkipVerify: true}
	_ = cfg

	dec := gob.NewDecoder(r.Body)
	var m Message
	dec.Decode(&m)

	body, _ := io.ReadAll(r.Body)
	var v Message
	xml.Unmarshal(body, &v)

	user := r.FormValue("u")
	log.Printf("login " + user)
}
