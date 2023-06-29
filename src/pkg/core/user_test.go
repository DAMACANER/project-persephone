package core

import (
	"context"
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
	suite.Server = httptest.NewServer(RouterFunc())
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
	jsonPayload := `
{
    "email":"crazyboycaner_featceza@hotmail.com",
    "username":"canercezarapyapardostlar",
    "password":"123$sagopaHaksizdi",
    "test":true,
    "phoneNumber": "+905555555555",
    "city": "BURSA",
    "country": "TURKEY"
}`
	reader := strings.NewReader(jsonPayload)
	req, err := suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", reader)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// delete the user again
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "crazyboycaner_featceza@hotmail.com"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)
	// now try without test: false, should return 200.
	jsonPayload = `
{
    "email":"crazyboycaner_featceza@hotmail.com",
    "username":"canercezarapyapardostlar",
    "password":"123$sagopaHaksizdi",
    "test":false,
    "phoneNumber": "+905555555555",
    "city": "BURSA",
    "country": "TURKEY"
}`
	reader = strings.NewReader(jsonPayload)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", reader)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now try register without deleting user, should return 400
	jsonPayload = `
{
    "email":"crazyboycaner_featceza@hotmail.com",
    "username":"canercezarapyapardostlar",
    "password":"123$sagopaHaksizdi",
    "test":false,
    "phoneNumber": "+905555555555",
    "city": "BURSA",
    "country": "TURKEY"
}`
	reader = strings.NewReader(jsonPayload)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", reader)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 400, req.StatusCode)
	// now try giving every field wrong for fiddling with validation, should return 400
	jsonPayload = `
{
    "email":"esrayibeklerken@sehitolduogullari.com",
    "username":"caneresrayibeklerkenserumtakilanogullari",
    "password":"bennapiyorumya",
    "test":false,
    "phoneNumber": "+905555555555",
    "city": "BAYBURT",
    "country": "ERENLI"
}`
	reader = strings.NewReader(jsonPayload)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", reader)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 400, req.StatusCode)
	// try giving every field wrong for fiddling with validation, but should return 200 due to test parameter.
	jsonPayload = `
{
    "email":"esrayibeklerken@sehitolduogullari.com",
    "username":"asd",
    "password":"bennapiyorumya",
    "test":true,
    "phoneNumber": "+905556555555",
    "city": "BAYBURT",
    "country": "ERENLI"
}`
	reader = strings.NewReader(jsonPayload)
	req, err = suite.Server.Client().Post(suite.Server.URL+"/api/user/signup", "application/json", reader)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 200, req.StatusCode)
	// now delete the user
	sql, args, err = suite.StmtBuilder.Delete("users").Where(squirrel.Eq{"email": "esrayibeklerken@sehitolduogullari.com"}).ToSql()
	assert.Nil(suite.T(), err)
	_, err = suite.DB.Exec(to, sql, args...)
	assert.Nil(suite.T(), err)

}

func TestUserCRUD(t *testing.T) {
	var testSuite = new(UserTestSuite)
	suite.Run(t, testSuite)
}
