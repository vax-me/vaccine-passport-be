package auth

import (
	"fmt"
	"github.com/form3tech-oss/jwt-go"
	"github.com/urfave/negroni"
	"net/http"
)

var defaultRoleExtractor = MongoEnvRoleExtractor{}

type RoleExtractor interface {
	HasRole(token *jwt.Token, role string) (bool, error)
	Init()
}

const doctorRoleName = "doctor"
const superUserRoleName = "su"

type RoleValidator = func(r *http.Request) bool

var DefaultRoleValidator = ValidateRole(defaultRoleExtractor)
var DefaultDoctorRoleValidator = DefaultRoleValidator(doctorRoleName)
var DefaultSuperUserRoleValidator = DefaultRoleValidator(superUserRoleName)

func AuthenticateCallAndCheckRole(handler http.HandlerFunc, validator RoleValidator) *negroni.Negroni {
	validatedHandler := func(w http.ResponseWriter, r *http.Request) {
		if !validator(r) {
			w.WriteHeader(403)
			_, _ = fmt.Fprint(w, "Forbidden.")
			return
		}
		handler(w, r)
	}
	return AuthenticateCall(validatedHandler)
}

func ValidateRole(extractor RoleExtractor) func(role string) RoleValidator {
	return func(role string) RoleValidator {
		return func(r *http.Request) bool {
			token, err := getTokenFromRequest(r)
			if err != nil {
				return false
			}
			hasRole, err := extractor.HasRole(token, role)
			return (err != nil) && hasRole
		}
	}
}

func GetRoleExtractor() RoleExtractor {
	return defaultRoleExtractor
}
