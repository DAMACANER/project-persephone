package core

import (
	"context"
	"encoding/json"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type UserTestSuite struct {
	suite.Suite
	Server      *httptest.Server
	DB          *pgxpool.Pool
	StmtBuilder squirrel.StatementBuilderType
}

func (suite *UserTestSuite) SetupSuite() {
	suite.Server = httptest.NewServer(HandlerFunc())
	db, err := GetPgPool()
	assert.Nil(suite.T(), err)
	stmt := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)
	suite.DB = db
	suite.StmtBuilder = stmt
}

func (suite *UserTestSuite) TestUserSignupHandler() {
	// before hand, delete our test user.
	sql, args, err := suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	// normal scenario, should return 200
	var payload UserSignupRequest
	payload.Email = "crazyboycaner_featceza@hotmail.com"
	payload.Username = "canercezarapyapardostlar"
	payload.Password = "123$sagopaHaksizdi"
	payload.Test = true
	payload.PhoneNum = "+905555555555"
	payload.City = "BURSA"
	payload.Country = "TURKEY"
	jsonPayload, err := json.Marshal(payload)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// delete the user again
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	// now try without test: false, should return 200.
	payload.Test = false
	jsonPayload, err = json.Marshal(payload)
	assert.Nil(suite.T(), err)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now try register without deleting user, with same payload, should return 400
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 400, req.StatusCode)
	// now try giving every field wrong for fiddling with validation, should return 400
	payload.Email = "esrayibeklerken@sehitolduogullari.com"
	payload.Username = "caneresrayibeklerkenserumtakilanogullari"
	payload.Password = "bennapiyorumya"
	payload.Test = false
	payload.PhoneNum = "+905555555555"
	payload.City = "BAYBURT"
	payload.Country = "ERENLI"
	jsonPayload, err = json.Marshal(payload)
	assert.Nil(suite.T(), err)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 400, req.StatusCode)
	// try giving every field wrong for fiddling with validation, but should return 200 due to test parameter.
	//
	// delete the user with the associated phone number first, due to phone number being unique constraint.
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"phone_number": "+905555555555"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	payload.Email = "esrayibeklerken@sehitolduogullari.com"
	payload.Username = "asd"
	payload.Password = "bennapiyorumya"
	payload.Test = true
	payload.PhoneNum = "+905555555555"
	payload.City = "BAYBURT"
	payload.Country = "ERENLI"
	jsonPayload, err = json.Marshal(payload)
	assert.Nil(suite.T(), err)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now delete the test users, for not creating clutter
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "esrayibeklerken@sehitolduogullari.com"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
}

func TestUserCRUD(t *testing.T) {
	var testSuite = new(UserTestSuite)
	suite.Run(t, testSuite)
}
