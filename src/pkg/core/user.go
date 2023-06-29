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
	"net"
	"net/http"
	"strings"
	"time"
)

func NewUserHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(AssignTracer("user", "USER_CRUD", "persephone-user-crud"))
	r.Post("/signup", UserSignupHandler)
	r.Post("/login", UserLoginHandler)
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
	ID              uuid.UUID  `db:"id"`
	Email           string     `db:"email"`
	Username        string     `db:"username"`
	Password        string     `db:"password"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
	PhoneNumber     string     `db:"phone_number"`
	Role            string     `db:"role"`
	PlaceID         *uuid.UUID `db:"place_id"`
	Banned          bool       `db:"banned"`
	Reputation      int16      `db:"reputation"`
	ReviewCount     int16      `db:"review_count"`
	SessionToken    string     `db:"session_token"`
	RefreshToken    string     `db:"refresh_token"`
	Location        *uuid.UUID `db:"location"`
	Verified        bool       `db:"verified"`
	LastLoginIP     net.IP     `db:"last_login_ip"`
	PossibleSpammer bool       `db:"possible_spammer"`
}

const (
	UserTableName          = "users"
	IDDBField              = "id"
	EmailDBField           = "email"
	UsernameDBField        = "username"
	PasswordDBField        = "password"
	CreatedAtDBField       = "created_at"
	UpdatedAtDBField       = "updated_at"
	PhoneNumberDBField     = "phone_number"
	RoleDBField            = "role"
	PlaceIDDBField         = "place_id"
	BannedDBField          = "banned"
	ReputationDBField      = "reputation"
	ReviewCountDBField     = "review_count"
	SessionTokenDBField    = "session_token"
	RefreshTokenDBField    = "refresh_token"
	LocationDBField        = "location"
	LastLoginIPDBField     = "last_login_ip"
	PossibleSpammerDBField = "possible_spammer"
	VerifiedDBField        = "verified"
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

type UserSignupResponse struct {
	User         UserDB `json:"user"`
	LoginToken   string `json:"loginToken"`
	RefreshToken string `json:"refreshToken"`
}

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
			err = fmt.Errorf("email %s already exists", signUpForm.Email)
			s.LogError(err, http.StatusBadRequest)
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
				err = fmt.Errorf("username %s already exists", signUpForm.Username)
				s.LogError(err, http.StatusBadRequest)
				return
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
	userData.Reputation = 0
	userData.CreatedAt = time.Now()
	userData.UpdatedAt = time.Now()
	userData.Role = "user"
	userData.ReviewCount = 0
	userData.ID, err = s.GetUniqueUUID(UserTableName, IDDBField)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	userData.Verified = false
	userData.ReviewCount = 0
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
	userData.Verified = false
	userData.PossibleSpammer = false
	// no place id at register
	userData.PlaceID = nil
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
	userData.Location = nil

	// insert the user
	user := s.StmtBuilder.Insert("users").
		Columns(
			IDDBField,
			EmailDBField,
			UsernameDBField,
			PasswordDBField,
			CreatedAtDBField,
			UpdatedAtDBField,
			PhoneNumberDBField,
			RoleDBField,
			BannedDBField,
			ReputationDBField,
			ReviewCountDBField,
			SessionTokenDBField,
			RefreshTokenDBField,
			LocationDBField,
			VerifiedDBField,
			PossibleSpammerDBField,
			PlaceIDDBField,
			LastLoginIPDBField).
		Values(
			userData.ID,
			userData.Email,
			userData.Username,
			userData.Password,
			userData.CreatedAt,
			userData.UpdatedAt,
			userData.PhoneNumber,
			userData.Role,
			userData.Banned,
			userData.Reputation,
			userData.ReviewCount,
			userData.SessionToken,
			userData.RefreshToken,
			userData.Location,
			userData.Verified,
			userData.PossibleSpammer,
			userData.PlaceID,
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

type UserSignInRequest struct {
	Email    string `json:"email" validate:"usernameOrEmailExists"`
	Username string `json:"username" validate:"usernameOrEmailExists"`
	Password string `json:"password" binding:"required"`
	Test     bool   `json:"test"`
}

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
		var signInForm UserSignInRequest
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
		ReviewCount int64     `json:"reviewCount"`
		ReviewIDs   []string  `json:"reviewIDs"`
		Location    struct {
			City    string `json:"city"`
			Country string `json:"country"`
		}
		Verified bool `json:"verified"`
	}
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
			fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
				IDDBField,
				EmailDBField,
				UsernameDBField,
				CreatedAtDBField,
				UpdatedAtDBField,
				PhoneNumberDBField,
				RoleDBField,
				BannedDBField,
				ReputationDBField,
				ReviewCountDBField,
				RefreshTokenDBField,
				VerifiedDBField)).
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
			&response.User.ReviewCount,
			&response.RefreshToken,
			&response.User.Verified)
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
