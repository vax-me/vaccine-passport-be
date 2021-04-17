package doctors

import (
	"encoding/json"
	"fmt"
	"github.com/kamva/mgm/v3"
	"github.com/kamva/mgm/v3/operator"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"strconv"
	"time"
)

type doctorPassportRelation struct {
	mgm.DefaultModel `json:"-" bson:",inline"`
	DoctorId         string `json:"doctor_id" bson:"doctor_id"`
	PassportId       string `json:"passport_id" bson:"passport_id"`
}
type InvalidPassport struct {
	mgm.DefaultModel `json:"-" bson:",inline"`
	PassportId       string `json:"passport_id" bson:"passport_id"`
	Timestamp        int64  `json:"unix_timestamp" bson:"unix_timestamp"`
}

type InvalidationRequest struct {
	DoctorId string `json:"doctor_id"`
}

func AddPassportToDoctor(DoctorId string, PassportId string) error {
	relation := &doctorPassportRelation{
		DoctorId:   DoctorId,
		PassportId: PassportId,
	}
	if err := mgm.Coll(relation).Create(relation); err != nil {
		return err
	}
	return nil
}

func invalidateDoctor(request InvalidationRequest) error {
	var result []doctorPassportRelation
	if err := mgm.Coll(&doctorPassportRelation{}).
		SimpleFind(&result, bson.M{"doctor_id": bson.M{operator.Eq: request.DoctorId}}); err != nil {
		return err
	}
	now := time.Now()
	if err := mgm.Transaction(func(session mongo.Session, sc mongo.SessionContext) error {
		for _, relation := range result {
			invalidPassport := &InvalidPassport{
				PassportId: relation.PassportId,
				Timestamp:  now.Unix(),
			}
			if err := mgm.Coll(invalidPassport).Create(invalidPassport); err != nil {
				return err
			}
		}
		return session.CommitTransaction(sc)
	}); err != nil {
		return err
	}
	return nil
}

func InvalidateDoctor(w http.ResponseWriter, r *http.Request) {
	// TODO Require super-user
	var req InvalidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, "Failed to read message")
		return
	}
	err := invalidateDoctor(req)
	if err != nil {
		w.WriteHeader(500)
		_, _ = fmt.Fprint(w, err)
		return
	}
	w.WriteHeader(204)
}

func GetInvalidPassports(w http.ResponseWriter, r *http.Request) {
	fromRaw := r.URL.Query().Get("from")
	from := int64(0)
	fromConv, err := strconv.ParseInt(fromRaw, 10, 64)
	if err == nil {
		from = fromConv
	}
	result := make([]InvalidPassport, 0) // Ensure slice is non-nil for return
	if err := mgm.Coll(&InvalidPassport{}).
		SimpleFind(&result, bson.M{"unix_timestamp": bson.M{operator.Gte: from}}); err != nil {
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		w.WriteHeader(500)
		log.Errorf("Failed to write response data")
		_, _ = fmt.Fprint(w, "Server failed to generate response.")
		return
	}
}
