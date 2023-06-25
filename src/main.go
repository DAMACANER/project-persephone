// Package Project Persephone, a food review backend.
package main

import (
	"context"
	"fmt"
	"github.com/go-co-op/gocron"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
	"persephone/pkg/backend"
	"persephone/pkg/core"
	"time"
)

func init() {
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
	// open init.sql and execute it
	//
	// but first, create city states and country tables
	CreateWorldTables()

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
		core.FetchPlaces(db)
	})
	if err != nil {
		log.Printf("error scheduling cron: %v", err)
		// dont panic, just log it
	}
	fmt.Println("Launching backend...")
	go func() {
		backend.LaunchBackend()
	}()
	s.StartAsync()
	s.StartBlocking()
}
func main() {}
