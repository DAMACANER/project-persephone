package core

import (
	"errors"
	"fmt"
	"time"
)

var emailIsSameWithRequestedError = errors.New("email is already same with requested")

var usernameIsSameWithRequestedError = errors.New("username is already same with requested")

var updatedRecentlyError = func(recentlyUpdatedProperty string, updatedAt time.Time, allowedInterval time.Duration) error {
	return fmt.Errorf("%s is updated recently, you can update it again after %s", recentlyUpdatedProperty, updatedAt.Add(allowedInterval).Sub(time.Now()))
}

var UUIDDoesNotExistError = func(uuidDNE string) error {
	return fmt.Errorf("uuid %s does not exist", uuidDNE)
}

var noRowsAffectedDuringUpdateError = errors.New("no rows affected during update")
var phoneNumberAlreadyExistsError = errors.New("phone number already exists") // Indicates that the phone number already exists in the system

var emailAlreadyExistsError = errors.New("email already exists") // Indicates that the email already exists in the system

var usernameAlreadyExistsError = errors.New("username already exists") // Indicates that the username already exists in the system

var userNotAllowedError = errors.New("user role not whitelisted") // Indicates that the user role is not allowed

var statusNotAllowedError = errors.New("token status not whitelisted") // Indicates that the token status is not allowed

type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}
