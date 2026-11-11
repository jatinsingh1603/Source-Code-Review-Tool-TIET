package web

import "net/http"

type statementHandler struct {
	region string
}

func (s statementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	w.Write([]byte(s.region + account))
}
