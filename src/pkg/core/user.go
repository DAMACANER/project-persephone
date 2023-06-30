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
	// declare routers with tracers wrapped around them
	r.With(signUpTracer).Post("/signup", UserSignupHandler)
	r.With(loginTracer).Post("/login", UserLoginHandler)
	r.With(updateTracer).Post("/update", UserUpdateHandler)

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
	Location              *uuid.UUID `db:"location"`
	Verified              bool       `db:"verified"`
	LastLoginIP           net.IP     `db:"last_login_ip"`
	LastLoginAt           time.Time  `db:"last_login_at"`
	PossibleSpammer       bool       `db:"possible_spammer"`
}

const (
	UserTableName                = "users"
	IDDBField                    = "id"
	EmailDBField                 = "email"
	UsernameDBField              = "username"
	PasswordDBField              = "password"
	CreatedAtDBField             = "created_at"
	UpdatedAtDBField             = "updated_at"
	PhoneNumberDBField           = "phone_number"
	RoleDBField                  = "role"
	PlaceIDDBField               = "place_id"
	BannedDBField                = "banned"
	ReputationDBField            = "reputation"
	SessionTokenDBField          = "session_token"
	RefreshTokenDBField          = "refresh_token"
	LocationDBField              = "location"
	LastLoginIPDBField           = "last_login_ip"
	PossibleSpammerDBField       = "possible_spammer"
	VerifiedDBField              = "verified"
	LastLoginAtDBField           = "last_login_at"
	EmailLastUpdatedAtDBField    = "email_last_updated_at"
	UsernameLastUpdatedAtDBField = "username_last_updated_at"
)

var onConflictColumns = []string{
	EmailDBField,
	UsernameDBField,
	PhoneNumberDBField,
}

var updateColumns = []string{
	IDDBField,
	UsernameDBField,
	PasswordDBField,
	CreatedAtDBField,
	UpdatedAtDBField,
	PhoneNumberDBField,
	RoleDBField,
	BannedDBField,
	ReputationDBField,
}

type UserSignupRequest struct {
	Email    string `json:"email" validate:"emailSpec" binding:"required"`
	Username string `json:"username" validate:"usernameSpec" binding:"required"`
	Password string `json:"password" validate:"passwordSpec" binding:"required"`
	Test     bool   `json:"test" validate:"boolean"`
	PhoneNum string `json:"phoneNumber" validate:"e164"`
	City     string `json:"city"`
	Country  string `json:"country"`
}

type UserSignupResponse GetUserDataResponse

func UserSignupHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var signUpForm UserSignupRequest
	if err := DecodeJSONBody(r, &signUpForm); err != nil {
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
			s.LogError(EmailAlreadyExistsError, http.StatusBadRequest)
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
				s.LogError(UsernameAlreadyExistsError, http.StatusBadRequest)
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
	userData.ID, err = s.GetUniqueUUID(UserTableName, IDDBField)
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
			IDDBField,
			EmailDBField,
			UsernameDBField,
			PasswordDBField,
			PhoneNumberDBField,
			RoleDBField,
			BannedDBField,
			SessionTokenDBField,
			RefreshTokenDBField,
			LocationDBField,
			LastLoginIPDBField).
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
			userData.Location,
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

type UserLoginRequest struct {
	Email    string `json:"email" validate:"usernameOrEmailExists"`
	Username string `json:"username" validate:"usernameOrEmailExists"`
	Password string `json:"password" binding:"required"`
	Test     bool   `json:"test"`
}

type UserLoginResponse GetUserDataResponse

func UserLoginHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var uid string
	if r.Header.Get("Authorization") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		jwtContents, err := s.GetJWTData(r)
		if err != nil {
			s.LogError(err, http.StatusBadRequest)
			return
		}
		TokenStatusWhitelist(jwtContents, []string{tokenStatusWaitingLogin})
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
		sqlBuilder := s.StmtBuilder.Select(fmt.Sprintf("%s, %s", PasswordDBField, IDDBField)).From("users")
		if signInForm.Email != "" {
			sqlBuilder = sqlBuilder.Where(squirrel.Eq{EmailDBField: signInForm.Email})
		} else if signInForm.Username != "" {
			sqlBuilder = sqlBuilder.Where(squirrel.Eq{UsernameDBField: signInForm.Username})
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

type UserUpdateRequest struct {
	Email    string `json:"email" validate:"usernameOrEmailExists"`
	Username string `json:"username" validate:"usernameOrEmailExists"`
	Test     bool   `json:"test"`
}
type UserUpdateDBFields struct {
	EmailLastUpdatedAt    time.Time `db:"email_last_updated_at"`
	UsernameLastUpdatedAt time.Time `db:"username_last_updated_at"`
	Email                 string    `db:"email"`
	Username              string    `db:"username"`
	SessionToken          string    `db:"session_token"`
}
type UserUpdateResponse GetUserDataResponse

func UserUpdateHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	jwtContents, err := s.GetJWTData(r)
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
	userQuery := s.StmtBuilder.Select(fmt.Sprintf("%s, %s, %s, %s, %s", EmailLastUpdatedAtDBField, UsernameLastUpdatedAtDBField, EmailDBField, UsernameDBField, SessionTokenDBField)).From("users").Where(squirrel.Eq{IDDBField: jwtContents.UUID})
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
				s.LogError(EmailIsSameWithRequestedError, http.StatusBadRequest)
				return
			}
			if time.Now().Sub(user.EmailLastUpdatedAt) < AllowedUsernameUpdateInterval {
				s.LogError(UpdatedRecentlyError("email", user.EmailLastUpdatedAt, AllowedUserEmailUpdateInterval), http.StatusBadRequest)
				return
			}
		}
		user.Email = req.Email
		user.EmailLastUpdatedAt = time.Now()
	}
	if req.Username != "" {
		if !req.Test {
			if req.Username == user.Username {
				s.LogError(UsernameIsSameWithRequestedError, http.StatusBadRequest)
				return
			}
			if time.Now().Sub(user.UsernameLastUpdatedAt) < AllowedUsernameUpdateInterval {
				s.LogError(UpdatedRecentlyError("username", user.UsernameLastUpdatedAt, AllowedUsernameUpdateInterval), http.StatusBadRequest)
				return
			}
		}
		user.Username = req.Username
		user.UsernameLastUpdatedAt = time.Now()
	}
	updateQuery := s.StmtBuilder.Update("users").SetMap(map[string]interface{}{
		EmailDBField:                 user.Email,
		UsernameDBField:              user.Username,
		EmailLastUpdatedAtDBField:    user.EmailLastUpdatedAt,
		UsernameLastUpdatedAtDBField: user.UsernameLastUpdatedAt,
	}).Where(squirrel.Eq{IDDBField: jwtContents.UUID})
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

type GetUserDataResponse struct {
	User struct {
		ID          string    `json:"id"`
		Email       string    `json:"email"`
		Username    string    `json:"username"`
		CreatedAt   time.Time `json:"createdAt"`
		UpdatedAt   time.Time `json:"updatedAt"`
		PhoneNumber string    `json:"phoneNumber"`
		Role        string    `json:"role"`
		Banned      bool      `json:"banned"`
		Reputation  int64     `json:"reputation"`
		Location    struct {
			City    string `json:"city"`
			Country string `json:"country"`
		}
		Verified              bool      `json:"verified"`
		EmailLastUpdatedAt    time.Time `json:"emailLastUpdatedAt"`
		UsernameLastUpdatedAt time.Time `json:"usernameLastUpdatedAt"`
		LastLoginAt           time.Time `json:"lastLoginAt"`
	} `json:"user"`
	SessionToken string `json:"sessionToken"`
	RefreshToken string `json:"refreshToken"`
}

func GetUser(r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	jwtContents, err := s.GetJWTData(r)
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	userFindQuery := s.StmtBuilder.
		Select(
			fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
				IDDBField,
				EmailDBField,
				UsernameDBField,
				CreatedAtDBField,
				UpdatedAtDBField,
				PhoneNumberDBField,
				RoleDBField,
				BannedDBField,
				ReputationDBField,
				RefreshTokenDBField,
				VerifiedDBField,
				EmailLastUpdatedAtDBField,
				UsernameLastUpdatedAtDBField,
				LastLoginAtDBField)).
		From(UserTableName).
		Where(squirrel.Eq{IDDBField: jwtContents.UUID})
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
		err := fmt.Errorf("uuid %s does not exist or it is not correct", jwtContents.UUID)
		s.LogError(err, http.StatusBadRequest)
		return
	}
	response.SessionToken = strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", -1)
	if s.WriteResponse(response, http.StatusOK) != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}

}
