package auth

import (
	"github.com/form3tech-oss/jwt-go"
	"net/http"
	"strings"
)

var defaultRoleExtractor = MongoEnvRoleExtractor{}

type RoleExtractor interface {
	HasRole(token *jwt.Token, role string) (bool, error)
	Init()
}

const doctorRoleName = "doctor"
const superUserRoleName = "su"

var CheckRoleDefault = CheckRole(defaultRoleExtractor)
var CheckRoleDefaultDoctor = CheckRoleDefault(doctorRoleName)
var CheckRoleDefaultSuperUser = CheckRoleDefault(superUserRoleName)

func CheckRole(extractor RoleExtractor) func(role string) func(r *http.Request) bool {
	return func(role string) func(r *http.Request) bool {
		return func(r *http.Request) bool {
			authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
			if len(authHeaderParts) < 2 {
				return false
			}
			tokenRaw := authHeaderParts[1]
			token, err := jwt.Parse(tokenRaw, verifyParseToken)
			hasRole, err := extractor.HasRole(token, role)
			return (err != nil) && hasRole
		}
	}
}

func GetRoleExtractor() RoleExtractor {
	return defaultRoleExtractor
}
