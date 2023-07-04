package core

import (
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/go-chi/chi/v5"
	"math"
	"net/http"
)

func NewCityHandler() http.Handler {
	r := chi.NewRouter()
	var getCitiesTracer = AssignTracer("/getCities", "WORLD_DATA", "GET_CITIES")
	var getStatesTracer = AssignTracer("/getStates", "WORLD_DATA", "GET_STATES")
	var getCountriesTracer = AssignTracer("/getCounties", "WORLD_DATA", "GET_COUNTRIES")
	r.With(JWTWhitelist([]string{tokenStatusActive}, nil)).Route("/", func(r chi.Router) {
		r.With(getCitiesTracer).Post("/getCities", GetCitiesHandler)
		r.With(getStatesTracer).Post("/getStates", GetStatesHandler)
		r.With(getCountriesTracer).Post("/getCountries", GetCountriesHandler)
	})
	return r
}

type City struct {
	ID          uint32  `json:"id" db:"id"`
	Name        string  `json:"name" db:"name"`
	StateID     uint32  `json:"state_id" db:"state_id"`
	StateCode   string  `json:"state_code" db:"state_code"`
	CountryID   uint32  `json:"country_id" db:"country_id"`
	CountryCode string  `json:"country_code" db:"country_code"`
	Latitude    float64 `json:"latitude" db:"latitude"`
	Longitude   float64 `json:"longitude" db:"longitude"`
}
type Cities []City

const (
	IDCityDBField          = "id"
	NameCityDBField        = "name"
	StateIDCityDBField     = "state_id"
	StateCodeCityDBField   = "state_code"
	CountryIDCityDBField   = "country_id"
	CountryCodeCityDBField = "country_code"
	LatitudeCityDBField    = "latitude"
	LongitudeCityDBField   = "longitude"
)

type GetCitiesRequest struct {
	Page     uint16 `json:"page" binding:"required" validate:"lt=65535,gt=0"`
	PageSize uint16 `json:"page_size" binding:"required" validate:"lt=65535,gt=0"`
	StateID  uint16 `json:"state_id" binding:"required" validate:"lt=65535,gt=0"`
}
type GetCitiesResponse struct {
	Cities      Cities `json:"cities"`
	ResultCount uint16 `json:"resultCount"`
	TotalCount  uint16 `json:"totalCount"`
	TotalPages  uint16 `json:"totalPages"`
}

func GetCitiesHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var req GetCitiesRequest
	if err := s.Bind(&req); err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	s.Validator.Struct(req)
	sql, args, err := s.StmtBuilder.
		Select(fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s, %s",
			IDCityDBField,
			NameCityDBField,
			StateIDCityDBField,
			StateCodeCityDBField,
			CountryIDCityDBField,
			CountryCodeCityDBField,
			LatitudeCityDBField,
			LongitudeCityDBField)).
		Where(squirrel.Eq{"state_id": req.StateID}).
		From("cities").
		Limit(uint64(req.PageSize)).
		Offset(uint64((req.Page - 1) * req.PageSize)).
		ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	rows, err := s.DB.Query(r.Context(), sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var cities []City
	for rows.Next() {
		var city City
		err := rows.Scan(&city.ID, &city.Name, &city.StateID, &city.StateCode, &city.CountryID, &city.CountryCode, &city.Latitude, &city.Longitude)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		cities = append(cities, city)
	}
	err = rows.Err()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	sqlCount, argsCount, errCount := s.StmtBuilder.
		Select("COUNT(*)").
		From("cities").
		Where(squirrel.Eq{"state_id": req.StateID}).
		ToSql()
	if errCount != nil {
		s.LogError(errCount, http.StatusInternalServerError)
		return
	}
	var count uint16
	err = s.DB.QueryRow(r.Context(), sqlCount, argsCount...).Scan(&count)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	var resp GetCitiesResponse
	resp.TotalCount = count
	resp.ResultCount = uint16(len(cities))
	resp.Cities = cities
	resp.TotalPages = count / req.PageSize
	s.WriteResponse(resp, http.StatusOK)

}

type State struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	CountryID   int    `json:"country_id"`
	CountryCode string `json:"country_code"`
	Latitude    string `json:"latitude"`
	Longitude   string `json:"longitude"`
}

type States []State

const (
	IDStateDBField          = "id"
	NameStateDBField        = "name"
	CountryIDStateDBField   = "country_id"
	CountryCodeStateDBField = "country_code"
	LatitudeStateDBField    = "latitude"
	LongitudeStateDBField   = "longitude"
)

type GetStatesRequest struct {
	Page      uint16 `json:"page" binding:"required" validate:"lt=65535,gt=0"`
	PageSize  uint16 `json:"page_size" binding:"required" validate:"lt=65535,gt=0"`
	CountryID uint16 `json:"country_id" binding:"required" validate:"lt=65535,gt=0"`
}
type GetStatesResponse struct {
	States      States `json:"states"`
	TotalCount  uint16 `json:"totalCount"`
	TotalPages  uint16 `json:"totalPages"`
	ResultCount uint16 `json:"resultCount"`
}

// GetStatesHandler godoc
//
//	@Summary		Get states
//	@Description	Get states
//	@Tags			World Data
//	@Accept			json
//	@Produce		json
//	@Body			{object} GetStatesRequest
//	@Router			/api/world/getStates [post]
//	@Success		200	{object}	GetStatesResponse
func GetStatesHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var req GetStatesRequest
	if err := s.Bind(&req); err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	sql, args, err := s.StmtBuilder.Select(fmt.Sprintf("%s, %s, %s, %s, %s, %s",
		IDStateDBField,
		NameStateDBField,
		CountryIDStateDBField,
		CountryCodeStateDBField,
		LatitudeStateDBField,
		LongitudeStateDBField)).
		From("states").
		Where(squirrel.Eq{"country_id": req.CountryID}).
		Limit(uint64(req.PageSize)).
		Offset(uint64((req.Page - 1) * req.PageSize)).
		ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	rows, err := s.DB.Query(r.Context(), sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var states []State
	for rows.Next() {
		var state State
		err := rows.Scan(&state.ID, &state.Name, &state.CountryID, &state.CountryCode, &state.Latitude, &state.Longitude)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		states = append(states, state)
	}
	err = rows.Err()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	sqlCount, argsCount, errCount := s.StmtBuilder.Select("COUNT(*)").
		From("states").
		Where(squirrel.Eq{"country_id": req.CountryID}).
		ToSql()
	if errCount != nil {
		s.LogError(errCount, http.StatusInternalServerError)
		return
	}
	var count uint16
	err = s.DB.QueryRow(r.Context(), sqlCount, argsCount...).Scan(&count)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}

	var resp GetStatesResponse
	resp.States = states
	resp.TotalCount = uint16(len(states))
	resp.ResultCount = uint16(len(states))
	resp.TotalPages = count / req.PageSize
	s.WriteResponse(resp, http.StatusOK)
}

type CountryInDB struct {
	ID             uint32   `json:"id" db:"id"`
	Name           string   `json:"name" db:"name"`
	ISO3           string   `json:"iso3,omitempty" db:"iso3"`
	NumericCode    string   `json:"numeric_code,omitempty" db:"numeric_code"`
	ISO2           string   `json:"iso2,omitempty" db:"iso2"`
	PhoneCode      string   `json:"phonecode,omitempty" db:"phonecode"`
	Capital        string   `json:"capital,omitempty" db:"capital"`
	Currency       string   `json:"currency,omitempty" db:"currency"`
	CurrencyName   string   `json:"currency_name,omitempty" db:"currency_name"`
	CurrencySymbol string   `json:"currency_symbol,omitempty" db:"currency_symbol"`
	TLD            string   `json:"tld,omitempty" db:"tld"`
	Native         string   `json:"native,omitempty" db:"native"`
	Region         string   `json:"region,omitempty" db:"region"`
	Subregion      string   `json:"subregion,omitempty" db:"subregion"`
	TimezoneID     []uint32 `json:"timezone_id,omitempty" db:"timezone_id"`
	Latitude       float64  `json:"latitude,omitempty" db:"latitude"`
	Longitude      float64  `json:"longitude,omitempty" db:"longitude"`
	Emoji          string   `json:"emoji,omitempty" db:"emoji"`
	EmojiU         string   `json:"emojiU,omitempty" db:"emojiU"`
}

type CountriesInDB []CountryInDB

const (
	IDCountryDBField             = "id"
	NameCountryDBField           = "name"
	ISO3CountryDBField           = "iso3"
	NumericCodeCountryDBField    = "numeric_code"
	ISO2CountryDBField           = "iso2"
	PhoneCodeCountryDBField      = "phonecode"
	CapitalCountryDBField        = "capital"
	CurrencyCountryDBField       = "currency"
	CurrencyNameCountryDBField   = "currency_name"
	CurrencySymbolCountryDBField = "currency_symbol"
	TLDCountryDBField            = "tld"
	NativeCountryDBField         = "native"
	RegionCountryDBField         = "region"
	SubregionCountryDBField      = "subregion"
	TimezoneIDCountryDBField     = "timezone_id"
	LatitudeCountryDBField       = "latitude"
	LongitudeCountryDBField      = "longitude"
	EmojiCountryDBField          = "emoji"
	EmojiUCountryDBField         = "emojiU"
)

type GetCountriesRequest struct {
	Page     uint16 `json:"page" binding:"required" validate:"lt=65535,gt=0"`
	PageSize uint16 `json:"page_size" binding:"required" validate:"lt=65535,gt=0"`
}

// GetCountriesResponse is the response body for GetCountriesHandler.
//
// swagger:model GetCountriesResponse
type GetCountriesResponse struct {
	// Countries represents a list of countries
	Countries CountriesInDB `json:"countries"`
	// TotalCount represents countries count in the database
	TotalCount uint16 `json:"totalCount"`
	// ResultCount represents Query result count
	ResultCount uint16 `json:"resultCount"`
	// TotalPages represents total number of pages, calculated by dividing TotalCount by PageSize in the GetCountriesRequest
	TotalPages uint16 `json:"totalPages"`
}

// GetCountriesHandler handles the HTTP request to get a paginated list of countries.
//
//	@Summary		Get Countries
//	@Description	Returns a paginated list of countries.
//	@Tags			World Data
//	@Accept			json
//	@Produce		json
//	@Body			{object} GetCountriesRequest
//	@Success		200	{object}	GetCountriesResponse
//	@Failure		400	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Router			/api/world/getCountries [post]
func GetCountriesHandler(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(ServerKeyString).(*Server)
	var req GetCountriesRequest
	if err := s.Bind(&req); err != nil {
		s.LogError(err, http.StatusBadRequest)
		return
	}
	sql, args, err := s.StmtBuilder.Select(fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
		IDCountryDBField,
		NameCountryDBField,
		ISO3CountryDBField,
		NumericCodeCountryDBField,
		ISO2CountryDBField,
		PhoneCodeCountryDBField,
		CapitalCountryDBField,
		CurrencyCountryDBField,
		CurrencyNameCountryDBField,
		CurrencySymbolCountryDBField,
		TLDCountryDBField,
		NativeCountryDBField,
		RegionCountryDBField,
		SubregionCountryDBField,
		TimezoneIDCountryDBField,
		LatitudeCountryDBField,
		LongitudeCountryDBField,
		EmojiCountryDBField,
		EmojiUCountryDBField)).
		From("countries").
		Limit(uint64(req.PageSize)).
		Offset(uint64((req.Page - 1) * req.PageSize)).
		ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	rows, err := s.DB.Query(r.Context(), sql, args...)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var countries CountriesInDB
	for rows.Next() {
		var country CountryInDB
		err := rows.Scan(&country.ID, &country.Name, &country.ISO3, &country.NumericCode, &country.ISO2, &country.PhoneCode, &country.Capital, &country.Currency, &country.CurrencyName, &country.CurrencySymbol, &country.TLD, &country.Native, &country.Region, &country.Subregion, &country.TimezoneID, &country.Latitude, &country.Longitude, &country.Emoji, &country.EmojiU)
		if err != nil {
			s.LogError(err, http.StatusInternalServerError)
			return
		}
		countries = append(countries, country)
	}
	err = rows.Err()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	sqlCount, args, err := s.StmtBuilder.Select("COUNT(*)").
		From("countries").
		ToSql()
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}
	var totalCount uint16
	err = s.DB.QueryRow(r.Context(), sqlCount, args...).Scan(&totalCount)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return
	}

	var resp GetCountriesResponse
	resp.Countries = countries
	resp.TotalCount = uint16(len(countries))
	resp.TotalPages = uint16(math.Ceil(float64(totalCount) / float64(req.PageSize)))
	resp.ResultCount = uint16(len(countries))
	s.WriteResponse(resp, http.StatusOK)
}
