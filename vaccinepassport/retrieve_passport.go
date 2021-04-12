package vaccinepassport

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func RetrievePassport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Invalid id")
		return
	}
	encryptedSignedVaccineDataContainer := &EncryptedSignedVaccineDataContainer{}
	if err := mgm.Coll(encryptedSignedVaccineDataContainer).FindByID(id, encryptedSignedVaccineDataContainer); err != nil {
		// TODO: Improve error handling
		log.Error(err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(encryptedSignedVaccineDataContainer); err != nil {
		w.WriteHeader(500)
		log.Errorf("Failed to write response data")
		_, _ = fmt.Fprint(w, "Server failed to generate response.")
		return
	}
}
