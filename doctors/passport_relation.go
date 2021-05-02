package doctors

import (
	"adrianlehmann.io/vaccine-passport-signing/common"
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
	mgm.DefaultModel `json:"-" bson:",inline"`
	DoctorId         string `json:"doctor_id" bson:"doctor_id"`
}

func CreateIndices() error {
	doctorIdAscIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"doctor_id": 1, // index in ascending order
		}, Options: nil,
	}
	_, err := mgm.Coll(&doctorPassportRelation{}).Indexes().CreateOne(mgm.Ctx(), doctorIdAscIndexModel)
	_, err = mgm.Coll(&InvalidationRequest{}).Indexes().CreateOne(mgm.Ctx(), doctorIdAscIndexModel)
	return err
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

func invalidateDoctor(request InvalidationRequest) (error, error) {
	// Check if doctor already invalid to avoid db fill up
	var prevInvalidReq []InvalidationRequest
	if err := mgm.Coll(&InvalidationRequest{}).SimpleFind(&prevInvalidReq, bson.M{"doctor_id": bson.M{operator.Eq: request.DoctorId}}); err == nil {
		if prevInvalidReq != nil && len(prevInvalidReq) > 0 {
			return fmt.Errorf("doctor already invalidated"), nil
		} else {
			_ = mgm.Coll(&InvalidationRequest{}).Create(&request) // Ok if failed - this is just a resource drain avoidance
		}
	}

	var result []doctorPassportRelation
	if err := mgm.Coll(&doctorPassportRelation{}).
		SimpleFind(&result, bson.M{"doctor_id": bson.M{operator.Eq: request.DoctorId}}); err != nil {
		return nil, err
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
		return nil, err
	}
	return nil, nil
}

func InvalidateDoctor(w http.ResponseWriter, r *http.Request) {
	// TODO Require super-user
	var req InvalidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.HttpError(w, 400, "Malformed body")
		return
	}
	userErr, serverErr := invalidateDoctor(req)
	if serverErr != nil {
		common.HttpErrorf(w, 500, "Could not invalidate doctor: %v", serverErr)
		return
	} else if userErr != nil {
		common.HttpErrorf(w, 400, "Could not invalidate doctor: %v", userErr)
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
		common.HttpError(w, 500, "Failed to get invalidated keys")
		log.Errorf("Failed to get invalidated keys: %v", err)
		return
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Errorf("Failed to write response data")
		common.HttpError(w, 500, "Server failed to generate response.")
		return
	}
}
