package core

import (
	"context"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"golang.org/x/exp/slices"
	"net/http"
	"time"

	_ "github.com/joho/godotenv/autoload"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

func AssignServer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server := &Server{}
		ctx := context.WithValue(r.Context(), ServerKeyString, server)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func AssignLogger() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server := r.Context().Value(ServerKeyString).(*Server)
			logger, err := zap.NewProduction()
			if err != nil {
				panic(err)
			}
			defer logger.Sync()
			sugar := logger.Sugar().WithOptions()
			server.Logger = sugar
			ctx := context.WithValue(r.Context(), ServerKeyString, server)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func AssignDB(db *pgxpool.Pool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server := r.Context().Value(ServerKeyString).(*Server)
			server.DB = db
			r = r.WithContext(context.WithValue(r.Context(), ServerKeyString, server))
			next.ServeHTTP(w, r)
		})
	}
}

func AssignTracer(endpoint string, group string, spanName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://localhost:14268/api/traces")))
		if err != nil {
			panic(err)
		}
		tracerProvider := tracesdk.NewTracerProvider(
			// Always be sure to batch in production.
			tracesdk.WithBatcher(exporter),
			// Record information about this application in a Resource.
			tracesdk.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceName("persephone"),
				attribute.String("environment", "dev"),
				attribute.String("endpoint", endpoint),
			)),
		)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tracerSpan := tracerProvider.Tracer(group)
			to, cancel := context.WithTimeout(context.Background(), time.Second*5)
			_, span := tracerSpan.Start(to, spanName)
			server := r.Context().Value(ServerKeyString).(*Server)
			server.Tracer = span
			ctx := context.WithValue(r.Context(), ServerKeyString, server)
			// Pass the span through the request.
			defer span.End()
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AssignValidator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value(ServerKeyString).(*Server)
		val, err := NewValidator()
		if err != nil {
			server.LogError(err, http.StatusInternalServerError)
		}
		server.Validator = val

		ctx := context.WithValue(r.Context(), ServerKeyString, server)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func AssignWriter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value(ServerKeyString).(*Server)
		server.Writer = w
		ctx := context.WithValue(r.Context(), ServerKeyString, server)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func AssignQueryBuilder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value(ServerKeyString).(*Server)
		server.StmtBuilder = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)
		ctx := context.WithValue(r.Context(), ServerKeyString, server)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
func RoleWhitelist(jwtContents JWTFields, role []string) bool {
	return slices.Contains(role, jwtContents.Role)
}

func TokenStatusWhitelist(jwtContents JWTFields, status []string) bool {
	return slices.Contains(status, jwtContents.Status)
}
