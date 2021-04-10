package vaccine_passport_signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type VaccineDataInput struct {
	Id   string `json:"id"`
	Type string `json:"type"`
}

type VaccineData struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Type      string `json:"type"`
}

type SignedVaccineData struct {
	EncodedData string
	TimeStamp   time.Time `json:"time_stamp"`
	Signature   string    `json:"signature"`
}

type EncryptedSignedVaccineDataContainer struct {
	mgm.DefaultModel `json:"-" bson:",inline"`
	Base64Data       string `json:"base_64_data" bson:"data"`
}

const ReservedSpacerChar = "⊕"

func validateVaccineDataInput(data VaccineDataInput) error {
	if matchString, err := regexp.MatchString("[0-9A-Fa-f]{24}", data.Id); err != nil || !matchString {
		if err != nil {
			log.Error(err)
		}
		return fmt.Errorf("invalid id")
	}
	if strings.Contains(data.Type, ReservedSpacerChar) {
		return fmt.Errorf("invalid character in use")
	}
	return nil
}

func Serialize(data VaccineData) string {
	return fmt.Sprintf("%s%s%s%s%s", data.FirstName, ReservedSpacerChar, data.LastName, ReservedSpacerChar, data.Type)
}

func GetPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyPath := os.Getenv("VaccinePassportPrivateKey")

	key, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {

		return nil, err
	}

	block, _ := pem.Decode(key)
	der, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return der, err
}

func Sign(data VaccineData) (SignedVaccineData, error) {
	privateKey, err := GetPrivateKey()
	if err != nil {
		panic(err)
	}
	signTime := time.Now()
	encodedData := Serialize(data)
	bodyHash, err := rsa.SignPKCS1v15(rand.Reader, privateKey,
		crypto.SHA256, []byte(encodedData))
	if err != nil {
		return SignedVaccineData{}, err
	}
	signedData := SignedVaccineData{EncodedData: encodedData, TimeStamp: signTime, Signature: string(bodyHash)}
	return signedData, nil
}

func Encrypt(signedData SignedVaccineData, key string) (*EncryptedSignedVaccineDataContainer, error) {
	publicKeyInterface, err := x509.ParsePKIXPublicKey([]byte(key))
	if err != nil {
		return nil, err
	}
	publicKey, isRSAPublicKey := publicKeyInterface.(*rsa.PublicKey)
	if !isRSAPublicKey {
		return nil, fmt.Errorf("public key parsed is not an RSA public key")
	}
	signedDataJson, err := json.Marshal(signedData)
	if err != nil {
		log.Error(err)
		return nil, fmt.Errorf("internal conversion error")
	}
	encryptedSignedDataJson, err := rsa.EncryptOAEP(
		sha512.New(),
		rand.Reader,
		publicKey,
		signedDataJson,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return &EncryptedSignedVaccineDataContainer{Base64Data: base64.StdEncoding.EncodeToString(encryptedSignedDataJson)}, nil
}

func SignVaccineData(w http.ResponseWriter, r *http.Request) {
	var payload VaccineDataInput
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Failed to read message")
		return
	}
	if err := validateVaccineDataInput(payload); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, err)
		return
	}
	passportRequest := &PassportRequest{}
	err := mgm.Coll(passportRequest).FindByID(payload.Id, passportRequest)
	if err != nil {
		log.Info(err)
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, "Could not find request with given id")
		return
	}

	data := VaccineData{}
	signed, err := Sign(data)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		_, _ = fmt.Fprint(w, "Server failed to sign.")
		return
	}
	encrypted, err := Encrypt(signed, passportRequest.PublicKey)
	encrypted.SetID(passportRequest.GetID())
	if err := mgm.Transaction(func(session mongo.Session, sc mongo.SessionContext) error {
		if err := mgm.Coll(encrypted).Create(encrypted); err != nil {
			return err
		}
		if err := mgm.Coll(passportRequest).Delete(passportRequest); err != nil {
			return err
		}
		return session.CommitTransaction(sc)
	}); err != nil {
		w.WriteHeader(500)
		log.Error(err)
		_, _ = fmt.Fprint(w, "Failed to store result")
		return
	}
	w.WriteHeader(204)
}
