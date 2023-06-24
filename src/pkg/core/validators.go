package core

import (
	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/go-playground/validator/v10"
	"unicode"
)

func NewValidator() (*validator.Validate, error) {
	validate := validator.New()

	// Register the custom validation function
	err := validate.RegisterValidation("passwordSpec", ValidatePassword)
	if err != nil {
		return nil, err
	}
	err = validate.RegisterValidation("emailSpec", ValidateEmail)
	if err != nil {
		return nil, err
	}
	err = validate.RegisterValidation("usernameSpec", ValidateUsername)
	if err != nil {
		return nil, err
	}
	err = validate.RegisterValidation("usernameOrEmailExists", ValidateUsernameOrEmailExists)
	return validate, nil
}

// ValidateUsername validates the username.
//
// No unicode characters allowed, i dont want usernames like this:
//
//	XxX_caner$$feat$$ceza$$sagopaya_olumune_diss_XxX
//
// Only letters and digits allowed.
//
// Username must be between 5 and 24 characters.
//
// Must not contain a non-english word. I cant give you an example for this, for... you already guessed the reason.
//
// Why 5? because I want caner to be a valid username. you expected a technical explanation? :)
func ValidateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	if len(username) < 5 || len(username) > 24 {
		return false
	}
	for _, char := range username {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return false
		}
		// if it contains a non english character:
		if char > unicode.MaxASCII {
			return false
		}
	}
	return true
}
func ValidateEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	verifier := emailverifier.NewVerifier()
	ret, err := verifier.Verify(email)
	if err != nil {
		return false
	}

	if !ret.Syntax.Valid {
		return false
	}
	if ret.Disposable {
		return false
	}
	if ret.Reachable != "unknown" || ret.Reachable != "yes" {
		return false
	}
	// TODO: smtp server for pinging the email to see if it exists, or it is alive.
	return true
}
func ValidatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	var (
		hasMinLength bool
		hasMaxLength bool
		hasUpper     bool
		hasLower     bool
		hasDigit     bool
		hasSymbol    bool
		minLength    = 8
		maxLength    = 24
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsSymbol(char) || unicode.IsPunct(char):
			hasSymbol = true
		}
	}

	length := len(password)
	if length >= minLength {
		hasMinLength = true
	}
	if length <= maxLength {
		hasMaxLength = true
	}

	return hasMinLength && hasMaxLength && hasUpper && hasLower && hasDigit && hasSymbol
}

func ValidateUsernameOrEmailExists(fl validator.FieldLevel) bool {
	currentField := fl.Field().String()
	if currentField == "username" {
		return ValidateUsername(fl)
	} else if currentField == "email" {
		return ValidateEmail(fl)
	} else {
		return false
	}
}
