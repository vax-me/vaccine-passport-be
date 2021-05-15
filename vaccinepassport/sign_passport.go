package vaccinepassport

import (
	"adrianlehmann.io/vaccine-passport-signing/auth"
	"adrianlehmann.io/vaccine-passport-signing/common"
	"adrianlehmann.io/vaccine-passport-signing/doctors"
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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"time"
)

type VaccineDose struct {
	Type         string `json:"type" bson:"type"`
	LotNo        string `json:"lot_no" bson:"lot_no"`
	Manufacturer string `json:"manufacturer" bson:"manufacturer"`
	DoseNo       uint32 `json:"dose_no" bson:"dose_no"`
}

type VaccineData struct {
	Name      string      `json:"name" bson:"name"`
	BirthDate Date        `json:"birth_date" bson:"birth_date"`
	Dose      VaccineDose `json:"dose" bson:"dose"`
}

type Date struct {
	Day   uint32 `json:"day" bson:"day"`
	Month uint32 `json:"month" bson:"month"`
	Year  uint32 `json:"year" bson:"year"`
}

type SignedVaccineData struct {
	EncodedData string    `json:"encoded_data_base_64"`
	TimeStamp   time.Time `json:"time_stamp"`
	Signature   string    `json:"signature_base_64"`
}

type EncryptedSignedVaccineDataContainer struct {
	mgm.DefaultModel      `json:"-" bson:",inline"`
	Base64EncryptedAESKey string `json:"base_64_encrypted_aes_key" bson:"encrypted_aes_key"`
	Base64Data            string `json:"base_64_data" bson:"data"`
	Base64Nonce           string `json:"base_64_nonce" bson:"nonce"`
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
		return SignedVaccineData{}, err
	}
	signTime := time.Now()
	_, encodedData, err := bson.MarshalValue(data)
	if err != nil {
		return SignedVaccineData{}, err
	}
	hashed := sha512.Sum512(encodedData)
	bodyHash, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed[:])
	if err != nil {
		return SignedVaccineData{}, err
	}
	signedData := SignedVaccineData{
		EncodedData: base64.StdEncoding.EncodeToString(encodedData),
		TimeStamp:   signTime,
		Signature:   base64.StdEncoding.EncodeToString(bodyHash),
	}
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
		Base64Nonce:           base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

func GetRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		common.HttpError(w, 400, "Invalid id")
		return
	}
	passportRequest := &PassportRequest{}
	err := mgm.Coll(passportRequest).FindByID(id, passportRequest)
	if err != nil {
		common.HttpError(w, 404, "Could not find request with given id")
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(passportRequest); err != nil {
		log.Errorf("Failed to write response data: %v", err)
		common.HttpError(w, 500, "Server failed to generate response.")
		return
	}
}

func SignVaccineData(w http.ResponseWriter, r *http.Request) {
	var payload VaccineDose
	id := mux.Vars(r)["id"]
	if err := ValidateId(id); err != nil {
		common.HttpError(w, 400, "Invalid id")
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		common.HttpError(w, 400, "Malformed body")
		return
	}
	passportRequest := &PassportRequest{}
	err := mgm.Coll(passportRequest).FindByID(id, passportRequest)
	if err != nil {
		log.Info(err)
		common.HttpError(w, 404, "Could not find request with given id")
		return
	}

	data := VaccineData{
		Name:      passportRequest.Name,
		BirthDate: passportRequest.BirthDate,
		Dose:      payload,
	}
	signed, err := sign(data)
	if err != nil {
		common.HttpError(w, 500, "Server failed to sign")
		log.Errorf("Server failed to sign: %v", err)
		return
	}
	encrypted, err := encrypt(signed, passportRequest.PublicKey)
	if err != nil {
		log.Errorf("Server failed to encrypt: %v", err)
		common.HttpError(w, 500, "Failed to encrypt result")
		return
	}
	doctorId, err := auth.GetRequestingEmail(r)
	if err != nil {
		common.HttpError(w, 400, "Could not identify doctor from token")
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
		if err := doctors.AddPassportToDoctor(doctorId, id); err != nil {
			return err
		}
		return session.CommitTransaction(sc)
	}); err != nil {
		log.Errorf("Failed to store passport: %v", err)
		common.HttpError(w, 500, "Failed to store passport")
		return
	}
	w.WriteHeader(204)
}
