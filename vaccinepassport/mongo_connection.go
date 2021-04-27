package vaccinepassport

import (
	"adrianlehmann.io/vaccine-passport-signing/doctors"
	"github.com/kamva/mgm/v3"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
)

func Init() {
	// Setup the mgm default config
	if err := mgm.SetDefaultConfig(nil, "mgm_lab", options.Client().ApplyURI(os.Getenv("VaccinePassportMongoUrl"))); err != nil {
		panic(err)
	}
	if err := doctors.CreateIndices(); err != nil {
		log.Fatalf("failed to created indices %v", err)
	}
}
