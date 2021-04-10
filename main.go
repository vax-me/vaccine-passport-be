package main

import (
	"adrianlehmann.io/vaccine-passport-signing/vaccinepassport"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	vaccinepassport.Init()
	r := mux.NewRouter()
	r.HandleFunc("/req", vaccinepassport.RequestPassport)
	r.HandleFunc("/ret", vaccinepassport.RetrievePassport)
	r.HandleFunc("/sign", vaccinepassport.SignVaccineData)
	http.Handle("/", r)
}
