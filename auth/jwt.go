package auth

import (
	"encoding/json"
	"errors"
	"github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/urfave/negroni"
	"net/http"
	"os"
	"strings"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var jwtMiddleware *jwtmiddleware.JWTMiddleware = nil

func AuthenticateCall(handler http.HandlerFunc) *negroni.Negroni {
	return negroni.New(
		negroni.HandlerFunc(GetJWTMiddleware().HandlerWithNext),
		negroni.Wrap(handler))
}

var aud = os.Getenv("VaccinePassportAuthAud")

func getTokenFromRequest(r *http.Request) (*jwt.Token, error) {
	authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authHeaderParts) < 2 {
		return nil, nil
	}
	tokenRaw := authHeaderParts[1]
	return jwt.Parse(tokenRaw, verifyParseToken)
}

func getRequestingEmail(r *http.Request) (string, error) {
	token, err := getTokenFromRequest(r)
	if err != nil {
		return "", err
	}
	return getEmail(token), nil
}

func getEmail(token *jwt.Token) string {
	return token.Claims.(jwt.MapClaims)["email"].(string)
}

func verifyParseToken(token *jwt.Token) (interface{}, error) {
	// Verify 'aud' claim
	checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
	if !checkAud {
		return token, errors.New("invalid audience")
	}
	// Verify 'iss' claim
	iss := "https://adrianleh.us.auth0.com/"
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
	if !checkIss {
		return token, errors.New("invalid issuer")
	}

	validErr := token.Claims.(jwt.MapClaims).Valid()
	if validErr != nil {
		return token, validErr
	}

	cert, err := getPemCert(token)
	if err != nil {
		panic(err.Error())
	}

	result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return result, nil
}

func GetJWTMiddleware() *jwtmiddleware.JWTMiddleware {
	if jwtMiddleware != nil {
		return jwtMiddleware
	}
	jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: verifyParseToken,
		SigningMethod:       jwt.SigningMethodRS256,
	})
	return jwtMiddleware
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://adrianleh.us.auth0.com/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}
