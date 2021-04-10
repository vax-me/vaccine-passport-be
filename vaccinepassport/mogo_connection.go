package vaccinepassport

import (
	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
)

func Init() {
	// Setup the mgm default config
	if err := mgm.SetDefaultConfig(nil, "mgm_lab", options.Client().ApplyURI(os.Getenv("VaccinePassportMongoUrl"))); err != nil {
		panic(err)
	}
}
