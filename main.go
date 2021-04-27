package main

import (
	"adrianlehmann.io/vaccine-passport-signing/auth"
	"adrianlehmann.io/vaccine-passport-signing/doctors"
	"adrianlehmann.io/vaccine-passport-signing/vaccinepassport"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	vaccinepassport.Init()
	r := mux.NewRouter()
	r.Handle("/req/{id}", auth.AuthenticateCall(vaccinepassport.GetRequest)).Methods(http.MethodGet)
	r.HandleFunc("/req", vaccinepassport.RequestPassport).Methods(http.MethodPost)
	r.HandleFunc("/ret/{id}", vaccinepassport.RetrievePassport).Methods(http.MethodGet)
	r.Handle("/sign/{id}", auth.AuthenticateCall(vaccinepassport.SignVaccineData)).Methods(http.MethodPost)
	r.Handle("/invalidate_doc", auth.AuthenticateCall(doctors.InvalidateDoctor)).Methods(http.MethodPost)
	r.HandleFunc("/invalid", doctors.GetInvalidPassports).Methods(http.MethodGet)
	http.ListenAndServe(":8010", r)
}
