package common

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type err struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func HttpErrorf(w http.ResponseWriter, status int, format string, args ...interface{}) {
	HttpError(w, status, fmt.Sprintf(format, args))
}

func HttpError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(err{
		Status:  status,
		Message: message,
	})
	if err != nil {
		w.WriteHeader(500)
		log.Errorf("Failed to write error %v", err)
	}
}
