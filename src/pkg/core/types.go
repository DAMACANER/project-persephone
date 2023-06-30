// Package core contains all the routers and the helper functions for routers.
package core

import (
	"github.com/Masterminds/squirrel"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
	"time"
)

var HandlerFunc = ReturnHandler

// types.go contains the most common types used in the routers. if a struct is used only in one handler, or
// strictly related to the handler, it will be defined in the handler file, usually at the top of the handler.
//
// please follow the same convention.

// Server , please dont assign Server fields without middlewares, it will cause a panic if you dont know what you are doing.
//
// Middleware initialization order:
//
//	AssignLogger("/signup")
//	AssignDB("users", client)
//	AssignTracer("/signup", "USER_SIGNUP")
type Server struct {
	// DB
	DB *pgxpool.Pool
	// Logger contains a SugaredLogger that is prefixed to the specific route specified in middleware initialization.
	//
	// Example:
	//
	//		router.Route("/core", func(r chi.Router) {
	//			r.Use(AssignLogger("/signup"))
	//			r.Use(AssignDB("users", client))
	//		})
	//
	// Will create a terminal-logger with the "/signup" as the prefix.
	//
	// So for any logging, you can access them like so:
	//
	//		func (s Server) CreateUser() {
	//			s.Logger.Info("User created")
	//		}
	Logger *zap.SugaredLogger
	// Tracer contains a Jaeger tracer that is used to trace the specific route specified in middleware initialization.
	//
	// Example:
	//
	//		router.Route("/core", func(r chi.Router) {
	//			r.Use(AssignTracer("/signup", "USER_SIGNUP"))
	//		})
	//
	// Will create a tracer with the "/signup" as an attribute that is sticked to the span, and USER_SIGNUP as the operation name.
	Tracer trace.Span
	// Validator contains a validator that is used to validate any struct with an example format of:
	// 		type UserSignupRequest struct {
	//			Email    string `json:"email" validate:"email" binding:"required"`
	//			Username string `json:"username" binding:"required"`
	//			Password string `json:"password" validate:"password" binding:"required"`
	//			Test     bool   `json:"test" validate:"boolean"`
	//		}
	//
	// Example:
	//
	//		var signUpForm UserSignupRequest
	//		if err := DecodeJSONBody(r, &signUpForm); err != nil {
	//			s.LogError(err, w, http.StatusBadRequest)
	//			return
	//		}
	//		err := s.Validator.Struct(signUpForm)
	//
	//

	Validator   *validator.Validate
	Writer      http.ResponseWriter
	StmtBuilder squirrel.StatementBuilderType
}

type serverKey string

const ServerKeyString serverKey = "server"

type JWTFields struct {
	// UUID is the id representing the user, and the key of the user in the database bucket "users"
	UUID string `json:"uuid"`
	// Expires shows the expiration datetime in unix.
	Expires int64  `json:"exp"`
	Role    string `json:"role"`
	Token   string `json:"token"`
	Status  string `json:"status"`
}

const (
	JWTUUIDKey    = "uuid"
	JWTExpiresKey = "exp"
	JWTRoleKey    = "role"
	JWTTokenKey   = "token"
	JWTStatusKey  = "status"
)

const (
	tokenDurationLogin   = 30 * time.Minute
	tokenDurationSession = 24 * time.Hour
	tokenDurationRefresh = 7 * 24 * time.Hour
)

const (
	tokenStatusActive       = "ACTIVE"
	tokenStatusWaitingLogin = "WAITING_LOGIN"
	tokenStatusRefresh      = "REFRESH"
)

const (
	JWT_ENCRYPT_ALGORITHM = "HS256"
	JWT_ENCRYPT_KEY       = "f18e90e9b71cf9af78022ef12350602d"
)

// for db
const (
	DBConnSSLDisabled = "disable"
	DBConnSSLEnabled  = "require"
)
const (
	DBPassword = "caner"
	DBUser     = "caner"
	DBPort     = 5432
	DBHost     = "localhost"
	DefaultDB  = "persephone"
)
