package main

import (
	"adrianlehmann.io/vaccine-passport-signing/vaccinepassport"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	vaccinepassport.Init()
	r := mux.NewRouter()
	r.HandleFunc("/req/{id}", vaccinepassport.GetRequest).Methods(http.MethodGet)
	r.HandleFunc("/req", vaccinepassport.RequestPassport).Methods(http.MethodPost)
	r.HandleFunc("/ret", vaccinepassport.RetrievePassport).Methods(http.MethodPost)
	r.HandleFunc("/sign", vaccinepassport.SignVaccineData).Methods(http.MethodPost)
	http.Handle("/", r)
}
