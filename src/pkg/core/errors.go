package core

import (
	"errors"
	"fmt"
	"time"
)

var EmailIsSameWithRequestedError = errors.New("email is already same with requested")

var UsernameIsSameWithRequestedError = errors.New("username is already same with requested")

var UpdatedRecentlyError = func(recentlyUpdatedProperty string, updatedAt time.Time, allowedInterval time.Duration) error {
	return fmt.Errorf("%s is updated recently, you can update it again after %s", recentlyUpdatedProperty, updatedAt.Add(allowedInterval).Sub(time.Now()))
}

var UUIDDoesNotExistsError = func(uuidDNE string) error {
	return fmt.Errorf("uuid %s does not exist", uuidDNE)
}
var EmailAlreadyExistsError = errors.New("email already exists")

var UsernameAlreadyExistsError = errors.New("username already exists")

var UserNotAllowed = errors.New("user role not whitelisted")

var StatusNotAllowed = errors.New("token status not whitelisted")

type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}
