package vaccinepassport

import (
	"adrianlehmann.io/vaccine-passport-signing/common"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func RetrievePassport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		common.HttpError(w, 400, "Invalid id")
		return
	}
	encryptedSignedVaccineDataContainer := &EncryptedSignedVaccineDataContainer{}
	if err := mgm.Coll(encryptedSignedVaccineDataContainer).FindByID(id, encryptedSignedVaccineDataContainer); err != nil {
		common.HttpError(w, 404, "Not found")
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(encryptedSignedVaccineDataContainer); err != nil {
		log.Errorf("Failed to write response data")
		common.HttpError(w, 500, "Server failed to respond")
		return
	}
}
