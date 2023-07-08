// Package Project Persephone, a food review backend.
package main

import (
	"context"
	"flag"
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

var initSQLLocation = flag.String("init-sql", "./init.sql", "location of init.sql file")
var statesJSONLocation = flag.String("states-json", "./states.json", "location of states.json file")
var countriesJSONLocation = flag.String("countries-json", "./countries.json", "location of countries.json file")
var citiesJSONLocation = flag.String("cities-json", "./cities.json", "location of cities.json file")
var jaegerEndpoint = flag.String("jaeger-endpoint", "http://localhost:14268/api/traces", "jaeger endpoint")

func init() {
	flag.Parse()
	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(*jaegerEndpoint)),
	)
	if err != nil {
		log.Fatal(err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
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
	sqlData, err := os.ReadFile(*initSQLLocation)
	if err != nil {
		panic(err)
	}
	sql := string(sqlData)
	_, err = conn.Exec(to, sql)
	if err != nil {
		panic(err)
	}
	CreateWorldTables(*statesJSONLocation, *countriesJSONLocation, *citiesJSONLocation, db)
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

func main() {}
