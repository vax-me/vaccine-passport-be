package vaccinepassport

import (
	"adrianlehmann.io/vaccine-passport-signing/common"
	"encoding/json"
	"fmt"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type PassportRequest struct {
	mgm.DefaultModel `json:"-" bson:",inline"`
	FirstName        string `json:"first_name" bson:"first_name"`
	LastName         string `json:"last_name" bson:"last_name"`
	PublicKey        string `json:"public_key" bson:"public_key"`
}

type PassportRequestInput struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	PublicKey string `json:"public_key"`
}

func validatePassportRequestInput(data PassportRequestInput) error {
	if len(data.FirstName) == 0 {
		return fmt.Errorf("first name must not be empty")
	}
	if len(data.LastName) == 0 {
		return fmt.Errorf("last name must not be empty")
	}
	return nil
}

func convertRequestInput(data PassportRequestInput) *PassportRequest {
	return &PassportRequest{
		FirstName: data.FirstName,
		LastName:  data.LastName,
		PublicKey: data.PublicKey,
	}
}

type IdObj struct {
	Id string `json:"id"`
}

func RequestPassport(w http.ResponseWriter, r *http.Request) {
	var payload PassportRequestInput
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		common.HttpError(w, 400, "Malformed body")
		return
	}
	if err := validatePassportRequestInput(payload); err != nil { // TODO: Validate cert
		common.HttpErrorf(w, 400, "%v", err)
		return
	}
	request := convertRequestInput(payload)
	if err := mgm.Coll(request).Create(request); err != nil {
		log.Error(err)
		common.HttpError(w, 500, "Failed to persist")
		return
	}
	w.WriteHeader(200)
	idObj := IdObj{
		Id: request.ID.Hex(),
	}
	if err := json.NewEncoder(w).Encode(idObj); err != nil {
		common.HttpError(w, 500, "Failed to write response data")
		log.Errorf("Failed to write response data %v", err)
		return
	}

}
