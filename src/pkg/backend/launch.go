// Package backend contains the launch function, middlewares, and helpers such as finding the .env file and the database file.
package backend

import (
	"context"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"net/http"
	"persephone/pkg/core"
	"time"
)

func LaunchBackend() {
	router := chi.NewRouter()
	//
	// PRE-SET MIDDLEWARES
	//
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	// please do not fiddle with middleware order.
	router.Use(core.AssignServer)
	router.Use(core.AssignWriter)
	router.Use(core.AssignLogger())
	router.Use(core.AssignValidator)
	router.Use(core.AssignQueryBuilder)

	//
	// POSTGRES CONNECTION POOL INITIALIZATION
	//
	db, err := pgxpool.New(context.Background(), core.GetPSQLConnString(core.SSLDisabled))
	if err != nil {
		panic(err)
	}
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// acquire a connection from the pool, just to test if it works
	conn, err := db.Acquire(to)
	if err != nil {
		panic(err)
	}
	if conn.Ping(to) != nil {
		panic(err)
	}
	conn.Release()
	router.Use(core.AssignDB(db))
	// terminate all connections and the pool when the program exits
	defer func(db *pgxpool.Pool, ctx context.Context) {
		db.Close()
	}(db, context.Background())
	// load the environment variables, .env in the main folder
	err = godotenv.Load(core.FindEnv())
	if err != nil {
		panic(err)
	}
	// MOUNT YOUR ROUTERS HERE.
	router.Route("/api", func(r chi.Router) {
		r.Mount("/user", core.NewUserHandler(db))
	})
	fmt.Println("Endpoints")
	fmt.Println("---------")
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("%s %s\n", method, route)
		return nil
	}

	if err := chi.Walk(router, walkFunc); err != nil {
		fmt.Printf("Logging err: %s\n", err.Error())
	}
	http.ListenAndServe(":3000", router)
}
