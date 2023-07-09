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

var UUIDDoesNotExistError = func(uuidDNE string) error {
	return fmt.Errorf("uuid %s does not exist", uuidDNE)
}

var PhoneNumberAlreadyExistsError = errors.New("phone number already exists")

var EmailAlreadyExistsError = errors.New("email already exists")

var UsernameAlreadyExistsError = errors.New("username already exists")

var UserDoesNotExistError = errors.New("user does not exist")

var UserNotAllowedError = errors.New("user role not whitelisted")

var NoAuthorizationHeaderError = errors.New("no Authorization header")

var UnexpectedSigningMethodError = func(expectedAlgorithm string, actualAlgorithm string) error {
	return fmt.Errorf("unexpected signing method, expected %s, got %s", expectedAlgorithm, actualAlgorithm)
}

var InvalidJWTTokenNoExpirationTimeError = errors.New("invalid JWT, no expiration time given in claims")

var InvalidJWTTokenExpiredError = errors.New("invalid JWT, token has expired")

var InvalidJWTGeneral = errors.New("invalid JWT")

type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}
