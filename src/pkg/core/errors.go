package core

import (
	"errors"
	"fmt"
	"time"
)

var EmailIsSameWithRequestedError = errors.New("email is already same with requested")

var UsernameIsSameWithRequestedError = errors.New("username is already same with requested")

var UpdatedRecentlyError = func(recentlyUpdatedProperty string, updatedAt time.Time, allowedInterval time.Duration) error {
	// for example, allowed interval is time.Hour * 72, and updatedAt is 2021-08-01 00:00:00
	//
	// calculate the remaining time:
	remainingTime := updatedAt.Add(allowedInterval).Sub(time.Now())
	return fmt.Errorf("%s is updated recently, you can update it again after %s", recentlyUpdatedProperty, remainingTime)
}

var EmailAlreadyExistsError = errors.New("email already exists")

var UsernameAlreadyExistsError = errors.New("username already exists")
