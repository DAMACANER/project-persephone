// Package backend contains the launch function, middlewares, and helpers such as finding the .env file and the database file.
package backend

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
	"persephone/pkg/core"
)

func LaunchBackend() {
	fmt.Println("Endpoints")
	fmt.Println("---------")
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("%s %s\n", method, route)
		return nil
	}
	router := core.RouterFunc()
	if err := chi.Walk(router, walkFunc); err != nil {
		fmt.Printf("Logging err: %s\n", err.Error())
	}
	http.ListenAndServe(":3000", router)
}
