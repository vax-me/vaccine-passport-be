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
	r.HandleFunc("/ret/{id}", vaccinepassport.RetrievePassport).Methods(http.MethodGet) // TODO: Make get and remove body
	r.HandleFunc("/sign", vaccinepassport.SignVaccineData).Methods(http.MethodPost)
	http.ListenAndServe(":8010", r)
}
