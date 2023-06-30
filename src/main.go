// Package Project Persephone, a food review backend.
package main

import (
	"context"
	"fmt"
	"github.com/go-co-op/gocron"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"log"
	"os"
	"persephone/pkg/backend"
	"persephone/pkg/core"
	"time"
)

func init() {
	// setup OTEL exporter, to be used in the tracer
	setupExporter()
	// get a new db connection and create city, state, and country tables
	db, err := pgxpool.New(context.Background(), core.GetPSQLConnString(core.DBConnSSLDisabled))
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
	if err = conn.Ping(to); err != nil {
		panic(err)
	}
	CreateWorldTables()
	// after being done, execute the init.sql for table/schema creation if not exists already.
	//
	// init.sql always lies in the src folder, so we can just read it from there.
	sqlData, err := os.ReadFile("./init.sql")
	if err != nil {
		panic(err)
	}
	sql := string(sqlData)
	_, err = conn.Exec(to, sql)
	if err != nil {
		panic(err)
	}
	// schedule any kind of crons you have below
	s := gocron.NewScheduler(time.UTC)
	_, err = s.Every(3).Days().SingletonMode().Do(func() {
		core.FetchPlaces()
	})
	if err != nil {
		log.Printf("error scheduling cron: %v", err)
		// dont panic, just log it
	}
	fmt.Println("Launching backend...")
	go func() {
		backend.LaunchBackend()
	}()
	// start executing cron jobs asynchronously and block the main thread while backend is running.
	s.StartAsync()
	s.StartBlocking()
}

func setupExporter() {
	endpoint := "http://localhost:14268/api/traces" // Jaeger endpoint

	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)),
	)
	if err != nil {
		log.Fatal(err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)

	otel.SetTracerProvider(tp)
}

func main() {}
