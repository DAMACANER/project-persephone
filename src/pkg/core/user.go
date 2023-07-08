package core

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func NewUserHandler() http.Handler {
	r := chi.NewRouter()
	var signUpTracer = AssignTracer("/signup", "USER_CRUD", "/signup")
	var loginTracer = AssignTracer("/login", "USER_CRUD", "/login")
	var updateTracer = AssignTracer("/update", "USER_CRUD", "/update")
	var deleteTracer = AssignTracer("/delete", "USER_CRUD", "/delete")
	// declare routers with tracers wrapped around them
	r.With(signUpTracer).Post("/signup", UserSignupHandler)
	r.With(loginTracer, JWTWhitelist([]string{tokenStatusWaitingLogin}, nil)).Post("/login", UserLoginHandler)
	r.With(updateTracer, JWTWhitelist([]string{tokenStatusActive}, nil)).Post("/update", UserUpdateHandler)
	r.With(deleteTracer, JWTWhitelist([]string{tokenStatusActive}, nil)).Delete("/delete", UserDeleteHandler)

	return r
}

const (
	roleAdmin     = "ADMIN"
	roleModerator = "MODERATOR"
	roleEditor    = "EDITOR"
	roleUser      = "USER"
	roleGuest     = "GUEST"
)

// UserDB represents the user in the database.
type UserDB struct {
	ID                    uuid.UUID  `db:"id"`
	Email                 string     `db:"email"`
	EmailLastUpdatedAt    time.Time  `db:"email_last_updated_at"`
	Username              string     `db:"username"`
	UsernameLastUpdatedAt time.Time  `db:"username_last_updated_at"`
	Password              string     `db:"password"`
	CreatedAt             time.Time  `db:"created_at"`
	UpdatedAt             time.Time  `db:"updated_at"`
	PhoneNumber           string     `db:"phone_number"`
	Role                  string     `db:"role"`
	PlaceID               *uuid.UUID `db:"place_id"`
	Banned                bool       `db:"banned"`
	Reputation            int16      `db:"reputation"`
	SessionToken          string     `db:"session_token"`
	RefreshToken          string     `db:"refresh_token"`
	City                  uint32     `db:"city"`
	Country               uint8      `db:"country"`
	State                 uint16     `db:"state"`
	Verified              bool       `db:"verified"`
	LastLoginIP           net.IP     `db:"last_login_ip"`
	LastLoginAt           time.Time  `db:"last_login_at"`
	PossibleSpammer       bool       `db:"possible_spammer"`
}

const (
	UserTableName                    = "users"
	UserIDDBField                    = "id"
	UserEmailDBField                 = "email"
	UserEmailLastUpdatedAtDBField    = "email_last_updated_at"
	UserUsernameDBField              = "username"
	UserUsernameLastUpdatedAtDBField = "username_last_updated_at"
	UserPasswordDBField              = "password"
	UserCreatedAtDBField             = "created_at"
	UserUpdatedAtDBField             = "updated_at"
	UserPhoneNumberDBField           = "phone_number"
	UserRoleDBField                  = "role"
	UserPlaceIDDBField               = "place_id"
	UserBannedDBField                = "banned"
	UserReputationDBField            = "reputation"
	UserSessionTokenDBField          = "session_token"
	UserRefreshTokenDBField          = "refresh_token"
	UserCityDBField                  = "city"
	UserCountryDBField               = "country"
	UserStateDBField                 = "state"
	UserVerifiedDBField              = "verified"
	UserLastLoginIPDBField           = "last_login_ip"
	UserLastLoginAtDBField           = "last_login_at"
	UserPossibleSpammerDBField       = "possible_spammer"
)

var onConflictColumns = []string{
	UserEmailDBField,
	UserUsernameDBField,
	UserPhoneNumberDBField,
}

// updateColumns is used when test parameter is given and we want to override an existing user.
//
// check onConflictColumns for the columns that are used for the conflict, if any of them is not unique, then first found user will be overwritten.
//
// delete any columns you want from here if you want to keep the old value.
var updateColumns = []string{
	UserIDDBField,
	UserUsernameDBField,
	UserPasswordDBField,
	UserCreatedAtDBField,
	UserUpdatedAtDBField,
	UserPhoneNumberDBField,
	UserRoleDBField,
	UserBannedDBField,
	UserReputationDBField,
	UserCityDBField,
	UserCountryDBField,
	UserStateDBField,
}

// UserSignupRequest represents the data required for user signup.
//
// swagger:model UserSignupRequest
type UserSignupRequest struct {
	// Email of the user.
	//
	// required: true
	// format: email
	Email string `json:"email" validate:"emailSpec" binding:"required"`

	// Username of the user.
	//
	// required: true
	Username string `json:"username" validate:"usernameSpec" binding:"required"`

	// Password of the user.
	//
	// required: true
	Password string `json:"password" validate:"passwordSpec" binding:"required"`

	// Test flag to indicate if it's a test.
	Test bool `json:"test" validate:"boolean"`

	// Phone number of the user.
	//
	// format: e164
	PhoneNum string `json:"phoneNumber" validate:"e164"`

	// City where the user is located.
	City uint32 `json:"city"`

	// Country where the user is located.
	Country uint8 `json:"country"`

	// State where the user is located.
	State uint16 `json:"state"`
}

type UserSignupResponse GetUserDataResponse

// UserSignupHandler handles the HTTP request for user signup.
//
//	@Summary		Handle user signup
//	@Description	Handles the HTTP request for user signup.
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			body	body		UserSignupRequest	true	"Signup form data"
//	@Success		200		{object}	GetUserDataResponse	"Successful signup"
//	@Failure		400		{object}	ErrorResponse		"Bad request or user already exists"
//	@Failure		500		{object}	ErrorResponse		"Internal server error"
//	@Router			/api/user/signup [post]
func UserSignupHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var signUpForm UserSignupRequest
	if err := s.Bind(&signUpForm); err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	if !signUpForm.Test {
		err := s.Validator.Struct(signUpForm)
		if err != nil {
			s.LogError(err, http.StatusBadRequest)
			return
		}
		// check if user exists
		user := s.StmtBuilder.Select("*").From("users").Where(squirrel.Eq{"email": signUpForm.Email})
		sql, args, err := user.ToSql()
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rows, err := s.DB.Query(to, sql, args...)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		if rows.Next() {
			s.LogError(emailAlreadyExistsError, http.StatusBadRequest)
			return
		} else {
			// now do the same check for user
			user = s.StmtBuilder.Select("*").From("users").Where(squirrel.Eq{"username": signUpForm.Username})
			sql, args, err = user.ToSql()
			if err != nil {
				s.LogError(err, http.StatusInternalServerError)
				return
			}
			to, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rows, err = s.DB.Query(to, sql, args...)
			if err != nil {
				s.LogError(err, http.StatusInternalServerError)
				return
			}
			if rows.Next() {
				s.LogError(usernameAlreadyExistsError, http.StatusBadRequest)
				return
			} else {
				// do the same check for phone number
				user = s.StmtBuilder.Select("*").From("users").Where(squirrel.Eq{"phone_number": signUpForm.PhoneNum})
				sql, args, err = user.ToSql()
				if err != nil {
					s.LogError(err, http.StatusInternalServerError)
					return
				}
				to, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
			}

		}
	}
	// dont check anything if test is true
	var userData UserDB
	passwordHashed, err := HashPassword(signUpForm.Password)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	userData.Password = passwordHashed
	userData.Email = signUpForm.Email
	userData.Username = signUpForm.Username
	userData.PhoneNumber = signUpForm.PhoneNum
	userData.Banned = false
	userData.Role = "user"
	userData.City = signUpForm.City
	userData.Country = signUpForm.Country
	userData.State = signUpForm.State
	userData.ID, err = s.GetUniqueUUID(UserTableName, UserIDDBField)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	userData.Verified = false
	tokenLoginInterface := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uuid":   userData.ID,
		"exp":    time.Now().Add(tokenDurationLogin).Unix(),
		"role":   roleUser,
		"status": tokenStatusWaitingLogin,
	})
	loginToken, err := tokenLoginInterface.SignedString([]byte(JWT_ENCRYPT_KEY))
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	refreshTokenInterface := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uuid":   userData.ID,
		"exp":    time.Now().Add(tokenDurationRefresh).Unix(),
		"role":   roleUser,
		"status": tokenStatusRefresh,
	})
	refreshToken, err := refreshTokenInterface.SignedString([]byte(JWT_ENCRYPT_KEY))
	userData.SessionToken = loginToken
	userData.RefreshToken = refreshToken
	// no place id at register
	loggedInIP := r.Header.Get("X-Forwarded-For")
	if loggedInIP == "" {
		loggedInIP = r.RemoteAddr
		if loggedInIP == "" {
			loggedInIP = "unknown"
		}
	}
	if loggedInIP != "unknown" {
		userData.LastLoginIP = net.ParseIP(loggedInIP)
	} else {
		userData.LastLoginIP = nil
	}

	// insert the user
	user := s.StmtBuilder.Insert("users").
		Columns(
			UserIDDBField,
			UserEmailDBField,
			UserUsernameDBField,
			UserPasswordDBField,
			UserPhoneNumberDBField,
			UserRoleDBField,
			UserBannedDBField,
			UserSessionTokenDBField,
			UserRefreshTokenDBField,
			UserCityDBField,
			UserCountryDBField,
			UserStateDBField,
			UserLastLoginIPDBField).
		Values(
			userData.ID,
			userData.Email,
			userData.Username,
			userData.Password,
			userData.PhoneNumber,
			userData.Role,
			userData.Banned,
			userData.SessionToken,
			userData.RefreshToken,
			userData.City,
			userData.Country,
			userData.State,
			userData.LastLoginIP,
		)
	sql, args, err := user.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.DB.Exec(to, sql, args...)
	if err != nil {
		if signUpForm.Test {
			// if test is true, add on conflict to the sql, so we can override the user.
			onConflictClause := fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET ", onConflictColumns[0])

			for i, col := range updateColumns {
				if i > 0 {
					onConflictClause += ", "
				}
				onConflictClause += fmt.Sprintf("%s = EXCLUDED.%s", col, col)
			}

			sql = fmt.Sprintf("%s %s", sql, onConflictClause)
			_, err = s.DB.Exec(to, sql, args...)
			if err != nil {
				s.LogError(err, http.StatusInternalServerError)
				return
			}
		} else {
			s.LogError(err, http.StatusBadRequest)
			return
		}
	}

	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", loginToken))
	GetUser(r)
}

// UserLoginRequest represents the data required for user login.
//
// swagger:model UserLoginRequest
type UserLoginRequest struct {
	// Email of the user.
	Email string `json:"email" validate:"usernameOrEmailExists"`

	// Username of the user.
	Username string `json:"username" validate:"usernameOrEmailExists"`

	// Password of the user.
	//
	// required: true
	Password string `json:"password" binding:"required"`

	// Test flag to indicate if it's a test.
	Test bool `json:"test"`
}

type UserLoginResponse GetUserDataResponse

// UserLoginHandler handles the HTTP request for user login.
//
//	@Summary		Handle user login
//	@Description	Handles the HTTP request for user login.
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			body	body		UserLoginRequest	true	"Login form data"
//	@Success		200		{object}	UserLoginResponse	"Successful login"
//	@Failure		400		{object}	ErrorResponse		"Bad request or unauthorized"
//	@Failure		500		{object}	ErrorResponse		"Internal server error"
//	@Router			/api/user/login [post]
func UserLoginHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var uid string
	if r.Header.Get("Authorization") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		jwtContents, err := s.GetJWTData()
		if err != nil {
			s.LogError(err, http.StatusBadRequest)
			return
		}
		uid = jwtContents.UUID
	} else {
		var signInForm UserLoginRequest
		err := json.NewDecoder(r.Body).Decode(&signInForm)
		if err != nil {
			s.LogError(err, http.StatusBadRequest)
			return
		}
		if !signInForm.Test {
			err = s.Validator.Struct(signInForm)
			if err != nil {
				s.LogError(err, http.StatusBadRequest)
				return
			}
		}
		sqlBuilder := s.StmtBuilder.Select(fmt.Sprintf("%s, %s", UserPasswordDBField, UserIDDBField)).From("users")
		if signInForm.Email != "" {
			sqlBuilder = sqlBuilder.Where(squirrel.Eq{UserEmailDBField: signInForm.Email})
		} else if signInForm.Username != "" {
			sqlBuilder = sqlBuilder.Where(squirrel.Eq{UserUsernameDBField: signInForm.Username})
		}
		sql, args, err := sqlBuilder.ToSql()
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var password string
		err = s.DB.QueryRow(to, sql, args...).Scan(&password, &uid)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(password), []byte(signInForm.Password))
		if err != nil {
			s.LogError(err, http.StatusUnauthorized)
			return
		}
	}
	tokenAuth := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uuid":   uid,
		"exp":    time.Now().Add(time.Hour * 24 * 30).Unix(),
		"role":   roleUser,
		"status": tokenStatusActive,
	})
	tokenToSend, err := tokenAuth.SignedString([]byte(JWT_ENCRYPT_KEY))
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenToSend))
	GetUser(r)
}

// UserUpdateRequest represents the request for updating user data.
type UserUpdateRequest struct {
	// User's email.
	//
	// This field is required and should be a valid email address.
	Email string `json:"email" validate:"usernameOrEmailExists"`

	// User's username.
	//
	// This field is required and should be a valid username.
	Username string `json:"username" validate:"usernameOrEmailExists"`

	// Test flag for testing purposes.
	Test bool `json:"test"`
}
type UserUpdateDBFields struct {
	EmailLastUpdatedAt    time.Time `db:"email_last_updated_at"`
	UsernameLastUpdatedAt time.Time `db:"username_last_updated_at"`
	Email                 string    `db:"email"`
	Username              string    `db:"username"`
	SessionToken          string    `db:"session_token"`
}
type UserUpdateResponse GetUserDataResponse

// UserUpdateHandler handles the user update request.
//
//	@Summary		Update User
//	@Description	Handles the request to update a user's email or username.
//	@Tags			User
//	@Param			Authorization		header		string				true	"JWT token"
//	@Param			userUpdateRequest	body		UserUpdateRequest	true	"User update data"
//	@Success		200					{object}	UserUpdateResponse	"Updated user data"
//	@Failure		400					{object}	ErrorResponse		"Bad request, may occur if the request is invalid, or user cant update username or email for now"
//	@Failure		401					{object}	ErrorResponse		"Unauthorized, may occur if the JWT token is invalid or expired"
//	@Failure		500					{object}	ErrorResponse		"Internal server error"
//	@Router			/api/user/update [post]
func UserUpdateHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	jwtContents, err := s.GetJWTData()
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
	}
	var req UserUpdateRequest
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyData, &req)
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	if !req.Test {
		err = s.Validator.Struct(req)
		if err != nil {
			s.LogError(err, http.StatusBadRequest)
			return
		}
	}
	var user UserUpdateDBFields
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	userQuery := s.StmtBuilder.
		Select(fmt.Sprintf("%s, %s, %s, %s, %s",
			UserEmailLastUpdatedAtDBField,
			UserUsernameLastUpdatedAtDBField,
			UserEmailDBField, UserUsernameDBField,
			UserSessionTokenDBField)).
		From("users").
		Where(squirrel.Eq{UserIDDBField: jwtContents.UUID})
	sql, args, err := userQuery.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	defer cancel()
	err = s.DB.QueryRow(to, sql, args...).Scan(&user.EmailLastUpdatedAt, &user.UsernameLastUpdatedAt, &user.Email, &user.Username, &user.SessionToken)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}

	if req.Email != "" {
		if !req.Test {
			if req.Email == user.Email {
				s.LogError(emailIsSameWithRequestedError, http.StatusBadRequest)
				return
			}
			if time.Now().Sub(user.EmailLastUpdatedAt) < AllowedUsernameUpdateInterval {
				s.LogError(updatedRecentlyError("email", user.EmailLastUpdatedAt, AllowedUserEmailUpdateInterval), http.StatusBadRequest)
				return
			}
		}
		user.Email = req.Email
		user.EmailLastUpdatedAt = time.Now()
	}
	if req.Username != "" {
		if !req.Test {
			if req.Username == user.Username {
				s.LogError(usernameIsSameWithRequestedError, http.StatusBadRequest)
				return
			}
			if time.Now().Sub(user.UsernameLastUpdatedAt) < AllowedUsernameUpdateInterval {
				s.LogError(updatedRecentlyError("username", user.UsernameLastUpdatedAt, AllowedUsernameUpdateInterval), http.StatusBadRequest)
				return
			}
		}
		user.Username = req.Username
		user.UsernameLastUpdatedAt = time.Now()
	}
	updateQuery := s.StmtBuilder.Update("users").SetMap(map[string]interface{}{
		UserEmailDBField:                 user.Email,
		UserUsernameDBField:              user.Username,
		UserEmailLastUpdatedAtDBField:    user.EmailLastUpdatedAt,
		UserUsernameLastUpdatedAtDBField: user.UsernameLastUpdatedAt,
	}).Where(squirrel.Eq{UserIDDBField: jwtContents.UUID})
	sql, args, err = updateQuery.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	_, err = s.DB.Exec(to, sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	GetUser(r)

}

// GetUserDataResponse represents the response data for retrieving user data.
//
// swagger:model GetUserDataResponse
type GetUserDataResponse struct {
	// User information.
	User struct {
		// User ID.
		ID string `json:"id"`

		// Email of the user.
		Email string `json:"email"`

		// Username of the user.
		Username string `json:"username"`

		// Timestamp indicating when the user was created.
		CreatedAt time.Time `json:"createdAt"`

		// Timestamp indicating when the user was last updated.
		UpdatedAt time.Time `json:"updatedAt"`

		// Phone number of the user.
		PhoneNumber string `json:"phoneNumber"`

		// Role of the user.
		Role string `json:"role"`

		// Flag indicating if the user is banned.
		Banned bool `json:"banned"`

		// Reputation of the user.
		Reputation int64 `json:"reputation"`

		// Location information of the user.
		Location struct {
			// City where the user is located.
			City string `json:"city"`

			// Country where the user is located.
			Country string `json:"country"`

			// State where the user is located.
			State string `json:"state"`
		} `json:"location"`

		// Flag indicating if the user is verified.
		Verified bool `json:"verified"`

		// Timestamp indicating when the email was last updated.
		EmailLastUpdatedAt time.Time `json:"emailLastUpdatedAt"`

		// Timestamp indicating when the username was last updated.
		UsernameLastUpdatedAt time.Time `json:"usernameLastUpdatedAt"`

		// Timestamp indicating when the user last logged in.
		LastLoginAt time.Time `json:"lastLoginAt"`
	} `json:"user"`

	// Session token for the user.
	SessionToken string `json:"sessionToken"`

	// Refresh token for the user.
	RefreshToken string `json:"refreshToken"`
}

func GetUser(r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	jwtContents, err := s.GetJWTData()
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	userFindQuery := s.StmtBuilder.
		Select(
			fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
				UserIDDBField,
				UserEmailDBField,
				UserUsernameDBField,
				UserCreatedAtDBField,
				UserUpdatedAtDBField,
				UserPhoneNumberDBField,
				UserRoleDBField,
				UserBannedDBField,
				UserReputationDBField,
				UserRefreshTokenDBField,
				UserVerifiedDBField,
				UserEmailLastUpdatedAtDBField,
				UserUsernameLastUpdatedAtDBField,
				UserLastLoginAtDBField)).
		From(UserTableName).
		Where(squirrel.Eq{UserIDDBField: jwtContents.UUID})
	sql, args, err := userFindQuery.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	user, err := s.DB.Query(to, sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	var response GetUserDataResponse
	if user.Next() {
		err = user.Scan(
			&response.User.ID,
			&response.User.Email,
			&response.User.Username,
			&response.User.CreatedAt,
			&response.User.UpdatedAt,
			&response.User.PhoneNumber,
			&response.User.Role,
			&response.User.Banned,
			&response.User.Reputation,
			&response.RefreshToken,
			&response.User.Verified,
			&response.User.EmailLastUpdatedAt,
			&response.User.UsernameLastUpdatedAt,
			&response.User.LastLoginAt)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
	} else {
		s.LogError(UUIDDoesNotExistError(jwtContents.UUID), http.StatusBadRequest)
		return
	}
	response.SessionToken = strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", -1)
	locationQuery := s.StmtBuilder.
		Select(fmt.Sprintf("%s.%s", StateTable, StateNameDBField),
			fmt.Sprintf("%s.%s", CityTable, CityNameDBField),
			fmt.Sprintf("%s.%s", CountryTable, CountryNameDBField)).
		From(UserTableName).
		Join(fmt.Sprintf("%s on %s.%s = %s.%s", StateTable, StateTable, StateIDDBField, UserTableName, UserStateDBField)).
		Join(fmt.Sprintf("%s on %s.%s = %s.%s", CityTable, CityTable, CityIDDBField, UserTableName, UserCityDBField)).
		Join(fmt.Sprintf("%s on %s.%s = %s.%s", CountryTable, CountryTable, CountryIDDBField, UserTableName, UserCountryDBField)).
		Where(squirrel.Eq{fmt.Sprintf("%s.%s", UserTableName, UserIDDBField): jwtContents.UUID})
	sql, args, err = locationQuery.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	location, err := s.DB.Query(to, sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	if location.Next() {
		err = location.Scan(&response.User.Location.State, &response.User.Location.City, &response.User.Location.Country)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
	}
	if s.WriteResponse(response, http.StatusOK) != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}

}

// UserDeleteResponse represents the response when a user is successfully deleted.
//
// swagger:response UserDeleteResponse
type UserDeleteResponse struct {
	// Success indicates if the user was deleted successfully.
	// Required: true
	Success bool `json:"success"`
}

// UserDeleteHandler deletes a user based on the provided JWT token.
//
// This endpoint deletes the user associated with the provided JWT token.
//
//	@Summary		Delete User
//	@Description	Deletes a user based on the provided JWT token.
//	@Tags			User
//	@Param			Authorization	header		string				true	"JWT token"
//	@Success		200				{object}	UserDeleteResponse	"User successfully deleted."
//	@Failure		400				{object}	ErrorResponse		"Bad request, may occur if the JWT token is invalid or expired"
//	@Failure		500				{object}	ErrorResponse		"Internal server error"
//	@Router			/api/user/delete [delete]
func UserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	jwtContents, err := s.GetJWTData()
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	deleteQuery := s.StmtBuilder.Delete(UserTableName).Where(squirrel.Eq{UserIDDBField: jwtContents.UUID})
	sql, args, err := deleteQuery.ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.DB.Exec(to, sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	err = s.WriteResponse(UserDeleteResponse{Success: true}, http.StatusOK)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
}
