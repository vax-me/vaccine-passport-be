package vaccinepassport

import (
	"adrianlehmann.io/vaccine-passport-signing/common"
	"encoding/json"
	"fmt"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
)

type PassportRequest struct {
	mgm.DefaultModel `json:"-" bson:",inline"`
	Name             string `json:"name" bson:"name"`
	BirthDate        Date   `json:"birth_date" bson:"birth_date"`
	PublicKey        string `json:"public_key" bson:"public_key"`
}

const publicKeyRegex = "(-----BEGIN PUBLIC KEY-----(\\n|\\r|\\r\\n)([0-9a-zA-Z\\+\\/=]{64}(\\n|\\r|\\r\\n))*([0-9a-zA-Z\\+\\/=]{1,63}(\\n|\\r|\\r\\n))?-----END PUBLIC KEY-----)"

func (data PassportRequest) validate() error {
	if len(data.Name) == 0 {
		return fmt.Errorf("last name must not be empty")
	}
	if strings.Contains(data.PublicKey, "BEGIN PRIVATE") {
		return fmt.Errorf("do not send private keys - please discard this key and regenerate")
	}
	matchString, err := regexp.MatchString(publicKeyRegex, data.PublicKey)
	if err != nil {
		log.Errorf("Regex pattern broken - omittting check: %v", err)
	}
	if err == nil && !matchString {
		return fmt.Errorf("malformed public key")
	}
	return nil
}

type IdObj struct {
	Id string `json:"id"`
}

func RequestPassport(w http.ResponseWriter, r *http.Request) {
	var request PassportRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		common.HttpError(w, 400, "Malformed body")
		return
	}
	if err := request.validate(); err != nil {
		common.HttpErrorf(w, 400, "%v", err)
		return
	}
	if err := mgm.Coll(&request).Create(&request); err != nil {
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
