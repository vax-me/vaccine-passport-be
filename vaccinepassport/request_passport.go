package vaccinepassport

import (
	"encoding/json"
	"fmt"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

type PassportRequest struct {
	mgm.DefaultModel `bson:",inline"`
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
	reservedCharInAnyField := strings.Contains(data.LastName, ReservedSpacerChar) ||
		strings.Contains(data.FirstName, ReservedSpacerChar)
	if reservedCharInAnyField {
		return fmt.Errorf("invalid character in use")
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
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Failed to read message")
		return
	}
	if err := validatePassportRequestInput(payload); err != nil { // TODO: Validate cert
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, err)
		return
	}
	request := convertRequestInput(payload)
	if err := mgm.Coll(request).Create(request); err != nil {
		w.WriteHeader(500)
		log.Error(err)
		_, _ = fmt.Fprint(w, "Failed to persist")
		return
	}
	w.WriteHeader(200)
	idObj := IdObj{
		Id: request.ID.String(),
	}
	if err := json.NewEncoder(w).Encode(idObj); err != nil {
		w.WriteHeader(500)
		log.Errorf("Failed to write response data")
		_, _ = fmt.Fprint(w, "Server failed to generate response.")
		return
	}

}
