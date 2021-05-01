package main

import (
	"adrianlehmann.io/vaccine-passport-signing/auth"
	"adrianlehmann.io/vaccine-passport-signing/doctors"
	"adrianlehmann.io/vaccine-passport-signing/vaccinepassport"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func main() {
	vaccinepassport.Init()
	auth.Init()
	auth.GetRoleExtractor().Init()
	r := mux.NewRouter()
	r.Handle("/req/{id}", auth.AuthenticateCallAndCheckRole(vaccinepassport.GetRequest, auth.DefaultDoctorRoleValidator)).Methods(http.MethodGet)
	r.HandleFunc("/req", vaccinepassport.RequestPassport).Methods(http.MethodPost)
	r.HandleFunc("/ret/{id}", vaccinepassport.RetrievePassport).Methods(http.MethodGet)
	r.Handle("/sign/{id}", auth.AuthenticateCallAndCheckRole(vaccinepassport.SignVaccineData, auth.DefaultDoctorRoleValidator)).Methods(http.MethodPost)
	r.Handle("/invalidate_doc", auth.AuthenticateCallAndCheckRole(doctors.InvalidateDoctor, auth.DefaultSuperUserRoleValidator)).Methods(http.MethodPost)
	r.HandleFunc("/invalid", doctors.GetInvalidPassports).Methods(http.MethodGet)
	r.Handle("/role", auth.AuthenticateCallAndCheckRole(auth.AddUserRoleHandler, auth.DefaultSuperUserRoleValidator)).Methods(http.MethodPost)
	log.Info("Ready to accept requests")
	err := http.ListenAndServe(":8010", r)
	if err != nil {
		panic(err)
	}
}
