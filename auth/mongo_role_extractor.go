package auth

import (
	"adrianlehmann.io/vaccine-passport-signing/common"
	"encoding/json"
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

type UserRole struct { // struct public for mgm
	mgm.DefaultModel `json:"-" bson:",inline"`
	Email            string `json:"email" bson:"email"`
	Role             string `json:"role" bson:"role"`
	AssignedBy       string `json:"-" bson:"assigned_by"`
}

func (MongoRoleExtractor) Init() {
	err := addIndices()
	if err != nil {
		log.Errorf("could not create role indicies %v", err)
	}
}

func addIndices() error {
	roleIndexModel := mongo.IndexModel{
		Keys: bson.D{
			{"email", 1}, // index in ascending order
			{"role", 1},
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
	return hasRole(role.Email, role.Role)
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
		common.HttpError(w, 400, "Malformed body")
		return
	}

	email, err := GetRequestingEmail(r)
	if err != nil {
		common.HttpError(w, 401, "Anonymous request")
		return
	}
	role.AssignedBy = email

	if exists, err := roleExists(role); err != nil || exists {
		common.HttpError(w, 400, "User already has role")
		return
	}
	if err := addUserRole(role); err != nil {
		common.HttpErrorf(w, 500, "Failed to add user: %v", err)
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
