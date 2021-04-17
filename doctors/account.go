package doctors

import (
	"github.com/kamva/mgm/v3"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type AccountInfo struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type StoredAccountInfo struct {
	mgm.DefaultModel `bson:",inline"`
	User             string `bson:"user"`
	Pass             []byte `bson:"pass"`
}

func (acc *AccountInfo) prepareForStore() (StoredAccountInfo, error) {
	hashedPw, err := bcrypt.GenerateFromPassword([]byte(acc.Pass), 15)
	if err != nil {
		return StoredAccountInfo{}, err
	}
	return StoredAccountInfo{User: acc.User, Pass: hashedPw}, nil
}

func Login(w http.ResponseWriter, r *http.Request) {
	//var acc StoredAccountInfo

}
