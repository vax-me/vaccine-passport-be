package auth

import (
	"encoding/json"
	"fmt"
	"github.com/form3tech-oss/jwt-go"
	"github.com/kamva/mgm/v3"
	"github.com/kamva/mgm/v3/operator"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"os"
)

type MongoRoleExtractor struct {
}

type UserRole struct {
	mgm.DefaultModel `bson:",inline"`
	email            string `bson:"email"`
	role             string `bson:"role"`
}

func (MongoRoleExtractor) Init() {
	err := addIndices()
	if err != nil {
		log.Fatalf("could not create role indicies %v", err)
	}
}

func addIndices() error {
	roleIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"email": 1, // index in ascending order
			"role":  1,
		}, Options: nil,
	}
	_, err := mgm.Coll(&UserRole{}).Indexes().CreateOne(mgm.Ctx(), roleIndexModel)
	return err
}

func (MongoRoleExtractor) HasRole(token *jwt.Token, role string) (bool, error) {
	email := getEmail(token)
	return hasRole(email, role)
}

func roleExists(role UserRole) (bool, error) {
	return hasRole(role.email, role.role)
}

func hasRole(email string, role string) (bool, error) {
	var ur *UserRole
	if err := mgm.Coll(ur).SimpleFind(ur, bson.M{"email": bson.M{operator.Eq: email}, "role": bson.M{operator.Eq: role}}); err != nil {
		return false, err
	}
	return (ur != nil), nil
}

func addUserRole(role UserRole) error {
	return mgm.Coll(&role).Create(&role)
}

func AddUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	var role UserRole
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		w.WriteHeader(400)
		return
	}
	if exists, err := roleExists(role); err != nil || exists {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "User already has role")
		return
	}
	if err := addUserRole(role); err != nil {
		w.WriteHeader(500)
		_, _ = fmt.Fprint(w, err)
		return
	}

	w.WriteHeader(204)
}

type MongoEnvRoleExtractor struct {
	roleExt MongoRoleExtractor
}

func (extractor MongoEnvRoleExtractor) HasRole(token *jwt.Token, role string) (bool, error) {
	email := getEmail(token)
	isSuperUserEmail := os.Getenv("VaccinePassportSUEmail") == email && role == superUserRoleName
	hasRole, err := extractor.roleExt.HasRole(token, role)
	return isSuperUserEmail || hasRole, err
}

func (extractor MongoEnvRoleExtractor) Init() {
	extractor.roleExt.Init()
}
