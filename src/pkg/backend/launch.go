// Package backend contains the launch function, middlewares, and helpers such as finding the .env file and the database file.
package backend

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
	"persephone/pkg/core"
)

func LaunchBackend() {
	handler := core.HandlerFunc()
	router := chi.NewRouter()
	router.Mount("/", handler)
	fmt.Printf("Server is running on port 3000\n")
	http.ListenAndServe(":3000", router)
}
