package core

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type UserTestSuite struct {
	suite.Suite
	Server       *httptest.Server
	DB           *pgxpool.Pool
	StmtBuilder  squirrel.StatementBuilderType
	SessionToken string
}

const (
	TestEmail    = "crazyboycaner_featceza@hotmail.com"
	TestPhone    = "+905555555555"
	TestPassword = "123$sagopaHaksizdi"
	TestUsername = "canercezarapyapardostlar"
	TestCity     = 32
	TestCountry  = 16
	TestState    = 1
)

func (suite *UserTestSuite) CleanClient() {
	suite.Server.Client().Transport.(*http.Transport).CloseIdleConnections()
}
func (suite *UserTestSuite) DeleteAndCreateUser() {
	sql, args, err := suite.StmtBuilder.Delete(UserTableName).Where(squirrel.Eq{UserEmailDBField: TestEmail}).ToSql()
	assert.Nil(suite.T(), err)
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.Nil(suite.T(), err)
	rows, err := suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	if rows.RowsAffected() == 0 {
		sql, args, err = suite.StmtBuilder.Delete(UserTableName).Where(squirrel.Eq{UserPhoneNumberDBField: TestPhone}).ToSql()
		assert.Nil(suite.T(), err)
		rows, err = suite.DB.Exec(to, sql, args...)
		assert.Nil(suite.T(), err)
		if rows.RowsAffected() == 0 {
			sql, args, err = suite.StmtBuilder.Delete(UserTableName).Where(squirrel.Eq{UserUsernameDBField: TestUsername}).ToSql()
			assert.Nil(suite.T(), err)
			rows, err = suite.DB.Exec(to, sql, args...)
			assert.Nil(suite.T(), err)
			if rows.RowsAffected() == 0 {
				suite.T().Error("Could not delete user")
			}
		}
	}
	var payloadSignup UserSignupRequest
	payloadSignup.Email = TestEmail
	payloadSignup.Username = TestUsername
	payloadSignup.Password = TestPassword
	payloadSignup.Test = true
	payloadSignup.PhoneNum = TestPhone
	payloadSignup.City = TestCity
	payloadSignup.Country = TestCountry
	payloadSignup.State = TestState
	jsonPayload, err := json.Marshal(payloadSignup)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	var resp UserSignupResponse
	err = json.NewDecoder(req.Body).Decode(&resp)
	assert.Nil(suite.T(), err)
	suite.SessionToken = resp.SessionToken
	suite.CleanClient()
}

func (suite *UserTestSuite) SetupSuite() {
	suite.Server = httptest.NewServer(HandlerFunc())
	db, err := GetPgPool()
	assert.Nil(suite.T(), err)
	stmt := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)
	suite.DB = db
	suite.StmtBuilder = stmt
}

// TestUserSignupHandler replicates a scenario where:
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
	suite.DeleteAndCreateUser()
}

// TestUserLoginWithSessionToken replicates a scenario where:
//
// -> User signs up
//
// -> Frontend saves the session token, redirects to the login page without a body or anything, only a session token.
func (suite *UserTestSuite) TestUserLoginWithSessionToken() {
	suite.DeleteAndCreateUser()
	draftReq, err := http.NewRequest("POST", suite.Server.URL+"/api/user/login", nil)
	assert.Nil(suite.T(), err)
	draftReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.SessionToken))
	loginReq, err := suite.Server.Client().Do(draftReq)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, loginReq.StatusCode)
}

// TestUserLoginWithEmailAndPassword replicates a scenario where:
//
// -> User created an account with email and password.
//
// -> Frontend didnt set the session token or we dont have a session token so we login with email and password.
func (suite *UserTestSuite) TestUserLoginWithEmailAndPassword() {
	suite.DeleteAndCreateUser()
	var payloadLogin UserLoginRequest
	payloadLogin.Email = TestEmail
	payloadLogin.Password = TestPassword
	payloadLogin.Test = true
	jsonPayload, err := json.Marshal(payloadLogin)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/login", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
}

// TestUserLoginWithUsernameAndPassword replicates a scenario where:
//
// -> User created an account with username and password.
//
// -> Frontend didnt set the session token or we dont have a session token so we login with username and password.
func (suite *UserTestSuite) TestUserLoginWithUsernameAndPassword() {
	suite.DeleteAndCreateUser()
	// now lets try to login without bearer token and only body variables.
	var payloadLogin UserLoginRequest
	payloadLogin.Username = TestUsername
	payloadLogin.Password = TestPassword
	payloadLogin.Test = true
	jsonPayload, err := json.Marshal(payloadLogin)
	assert.Nil(suite.T(), err)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/login", "application/json", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
}

func (suite *UserTestSuite) TestEmailAndPasswordUpdate() {
	suite.DeleteAndCreateUser()
	// first, we will change username and email to something different with test parameter set to true.
	var payloadUpdate UserUpdateRequest
	payloadUpdate.Email = "zattiri"
	payloadUpdate.Username = "zort"
	payloadUpdate.Test = true
	jsonPayload, err := json.Marshal(payloadUpdate)
	assert.Nil(suite.T(), err)
	draftReq, err := http.NewRequest("POST", suite.Server.URL+"/api/user/update", strings.NewReader(string(jsonPayload)))
	draftReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.SessionToken))
	req, err := suite.Server.Client().Do(draftReq)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	var respUpdate UserUpdateResponse
	bodyData, err := io.ReadAll(req.Body)
	assert.Nil(suite.T(), err)
	err = json.Unmarshal(bodyData, &respUpdate)
	assert.Nil(suite.T(), err)
	assert.NotEqual(suite.T(), respUpdate.User.Email, TestEmail)
	assert.NotEqual(suite.T(), respUpdate.User.Username, TestUsername)
	// hit the same payload with test set to false, it should return 400, due to users having to wait 7 days to change email.
	payloadUpdate.Test = false
	jsonPayload, err = json.Marshal(payloadUpdate)
	assert.Nil(suite.T(), err)
	draftReq, err = http.NewRequest("POST", suite.Server.URL+"/api/user/update", strings.NewReader(string(jsonPayload)))
	assert.Nil(suite.T(), err)
	draftReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.SessionToken))
	req, err = suite.Server.Client().Do(draftReq)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 400, req.StatusCode)

}

func TestUserCRUD(t *testing.T) {
	var testSuite = new(UserTestSuite)
	suite.Run(t, testSuite)
}
