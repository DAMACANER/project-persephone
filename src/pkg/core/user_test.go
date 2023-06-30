package core

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"net/http"
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

// TestUserSignupHandler replicates where:
//
// -> User signs up with a valid payload.
//
// -> User signs up with an invalid payload.
//
// -> User tries to signs up with an existing email/phone.
//
// -> Validators are working, and invalid payloads are rejected.
//
// -> We can override the existing user if frontend sets the test flag to true.
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
	// now try register without deleting user, with same payload only setting test to false, should return 400
	payload.Test = false
	jsonPayload, err = json.Marshal(payload)
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

// TestUserLoginWithSessionToken replicates a scenario where:
//
// -> User signs up
//
// -> Frontend saves the session token, redirects to the login page without a body or anything, only a session token.
func (suite *UserTestSuite) TestUserLoginWithSessionToken() {
	var payloadSignup UserSignupRequest
	payloadSignup.Email = "crazyboycaner_featceza@hotmail.com"
	payloadSignup.Username = "canercezarapyapardostlar"
	payloadSignup.Password = "123$sagopaHaksizdi"
	payloadSignup.Test = true
	payloadSignup.PhoneNum = "+905555555555"
	payloadSignup.City = "BURSA"
	payloadSignup.Country = "TURKEY"
	jsonPayload, err := json.Marshal(payloadSignup)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	var resp UserSignupResponse
	err = json.NewDecoder(req.Body).Decode(&resp)
	assert.Nil(suite.T(), err)
	// first of all, check if session token login is working.
	//
	// warning that httptest is for incoming requests, not outgoing requests.
	draftReq, err := http.NewRequest("POST", suite.Server.URL+"/api/user/login", nil)
	assert.Nil(suite.T(), err)
	draftReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", resp.SessionToken))
	loginReq, err := suite.Server.Client().Do(draftReq)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, loginReq.StatusCode)
	// delete the user
	sql, args, err := suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
}

// TestUserLoginWithEmailAndPassword replicates a scenario where:
//
// -> User created an account with email and password.
//
// -> Frontend didnt set the session token or we dont have a session token so we login with email and password.
func (suite *UserTestSuite) TestUserLoginWithEmailAndPassword() {
	// first of all, create a user.
	var payloadSignup UserSignupRequest
	payloadSignup.Email = "crazyboycaner_featceza@hotmail.com"
	payloadSignup.Username = "canercezarapyapardostlar"
	payloadSignup.Password = "123$sagopaHaksizdi"
	payloadSignup.Test = true
	payloadSignup.PhoneNum = "+905555555555"
	payloadSignup.City = "BURSA"
	payloadSignup.Country = "TURKEY"
	jsonPayload, err := json.Marshal(payloadSignup)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now lets try to login without bearer token and only body variables.
	var payloadLogin UserLoginRequest
	payloadLogin.Email = "crazyboycaner_featceza@hotmail.com"
	payloadLogin.Password = "123$sagopaHaksizdi"
	payloadLogin.Test = true
	jsonPayload, err = json.Marshal(payloadLogin)
	assert.Nil(suite.T(), err)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/login", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// and delete the test user
	sql, args, err := suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
}

// TestUserLoginWithUsernameAndPassword replicates a scenario where:
//
// -> User created an account with username and password.
//
// -> Frontend didnt set the session token or we dont have a session token so we login with username and password.
func (suite *UserTestSuite) TestUserLoginWithUsernameAndPassword() {
	// first of all, create a user.
	var payloadSignup UserSignupRequest
	payloadSignup.Email = "crazyboycaner_featceza@hotmail.com"
	payloadSignup.Username = "canercezarapyapardostlar"
	payloadSignup.Password = "123$sagopaHaksizdi"
	payloadSignup.Test = true
	payloadSignup.PhoneNum = "+905555555555"
	payloadSignup.City = "BURSA"
	payloadSignup.Country = "TURKEY"
	jsonPayload, err := json.Marshal(payloadSignup)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now lets try to login without bearer token and only body variables.
	var payloadLogin UserLoginRequest
	payloadLogin.Username = "canercezarapyapardostlar"
	payloadLogin.Password = "123$sagopaHaksizdi"
	payloadLogin.Test = true
	jsonPayload, err = json.Marshal(payloadLogin)
	assert.Nil(suite.T(), err)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/login", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// and delete the test user
	sql, args, err := suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
}

func TestUserCRUD(t *testing.T) {
	var testSuite = new(UserTestSuite)
	suite.Run(t, testSuite)
}
