package vaccinepassport

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
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

// TODO: The methods in these files need doctor auth!

type VaccineDataInput struct {
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
	mgm.DefaultModel      `json:"-" bson:",inline"`
	Base64EncryptedAESKey string `json:"base_64_encrypted_aes_key" bson:"encrypted_aes_key"`
	Base64Data            string `json:"base_64_data" bson:"data"`
}

const ReservedSpacerChar = "⊕"

func validateVaccineDataInput(data VaccineDataInput) error {
	if strings.Contains(data.Type, ReservedSpacerChar) {
		return fmt.Errorf("invalid character in use")
	}
	return nil
}

func ValidateId(id string) error {
	if matchString, err := regexp.MatchString("[0-9A-Fa-f]{24}", id); err != nil || !matchString {
		if err != nil {
			log.Error(err)
		}
		return fmt.Errorf("invalid id")
	}
	return nil
}

func Serialize(data VaccineData) string {
	return fmt.Sprintf("%s%s%s%s%s", data.FirstName, ReservedSpacerChar, data.LastName, ReservedSpacerChar, data.Type)
}

var privKey = (*rsa.PrivateKey)(nil)

func getPrivateKey() (*rsa.PrivateKey, error) {
	if privKey != nil {
		return privKey, nil
	}
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
	privKey = der
	return der, err
}

func sign(data VaccineData) (SignedVaccineData, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		panic(err)
	}
	signTime := time.Now()
	encodedData := Serialize(data)
	hashed := sha512.Sum512([]byte(encodedData))
	bodyHash, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed[:])
	if err != nil {
		return SignedVaccineData{}, err
	}
	signedData := SignedVaccineData{EncodedData: encodedData, TimeStamp: signTime, Signature: string(bodyHash)}
	return signedData, nil
}

func randBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encrypt(signedData SignedVaccineData, key string) (*EncryptedSignedVaccineDataContainer, error) {
	pemBlock, _ := pem.Decode([]byte(key))
	if pemBlock == nil {
		return nil, fmt.Errorf("could not find PEM")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
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

	aesKey, err := randBytes(32)
	if err != nil {
		return nil, err
	}
	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonce, err := randBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	c := gcm.Seal(nil, nonce, signedDataJson, nil)
	encryptedSignedDataJson := append(nonce, c...)

	encryptedAESKey, err := rsa.EncryptOAEP(
		sha512.New(),
		rand.Reader,
		publicKey,
		aesKey,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return &EncryptedSignedVaccineDataContainer{
		Base64Data:            base64.StdEncoding.EncodeToString(encryptedSignedDataJson),
		Base64EncryptedAESKey: base64.StdEncoding.EncodeToString(encryptedAESKey),
	}, nil
}

func GetRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Invalid id")
		return
	}
	passportRequest := &PassportRequest{}
	err := mgm.Coll(passportRequest).FindByID(id, passportRequest)
	if err != nil {
		log.Info(err)
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, "Could not find request with given id")
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(passportRequest); err != nil {
		w.WriteHeader(500)
		log.Errorf("Failed to write response data")
		_, _ = fmt.Fprint(w, "Server failed to generate response.")
		return
	}
}

func SignVaccineData(w http.ResponseWriter, r *http.Request) {
	var payload VaccineDataInput
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Invalid id")
		return
	}
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
	err := mgm.Coll(passportRequest).FindByID(id, passportRequest)
	if err != nil {
		log.Info(err)
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, "Could not find request with given id")
		return
	}

	data := VaccineData{}
	signed, err := sign(data)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		_, _ = fmt.Fprint(w, "Server failed to sign.")
		return
	}
	encrypted, err := encrypt(signed, passportRequest.PublicKey)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		_, _ = fmt.Fprint(w, "Failed to encrypt result")
		return
	}
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
