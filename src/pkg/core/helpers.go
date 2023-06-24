package core

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/qedus/osmpbf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func (s Server) LogError(err error, httpCode int) {
	// dont log if middleware is not yet initialized
	if s.Tracer != nil {
		s.Tracer.SetAttributes(attribute.KeyValue{
			Key: "err", Value: attribute.StringValue(err.Error()),
		})
		s.Tracer.SetStatus(codes.Error, err.Error())
	}
	if s.Logger != nil {
		s.Logger.Error(err)
	}
	if s.Writer != nil {
		s.Logger.Error(err)
		s.Writer.WriteHeader(httpCode)
		var errJSON = struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}
		errMessageJSON, _ := json.Marshal(errJSON)
		s.Writer.Write(errMessageJSON)
	}
}
func (s Server) WriteResponse(response interface{}, httpCode int) error {
	resp, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return err
	}
	s.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")

	s.Writer.WriteHeader(httpCode)
	// write response as JSON
	_, err = s.Writer.Write(resp)
	if err != nil {
		s.LogError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}
func (s Server) ServerHealthCheck() (bool, error) {
	to, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	err := s.DB.Ping(to)
	if err != nil {
		return false, err
	}
	// check if logger is working
	err = s.Logger.Sync()
	if err != nil {
		return false, err
	}
	return true, nil
}

func DecodeJSONBody(r *http.Request, desiredStruct interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	// Remove invalid characters from the JSON body
	cleanBody := removeInvalidCharacters(body)

	err = json.Unmarshal(cleanBody, desiredStruct)
	if err != nil {
		return errors.New("failed to parse JSON body")
	}

	return nil
}

// removeInvalidCharacters removes invalid characters from the JSON body.
func removeInvalidCharacters(body []byte) []byte {
	// Define invalid characters you want to remove from the JSON body
	invalidChars := []byte{'\n', '\r'}

	// Remove invalid characters
	cleanedBody := make([]byte, 0, len(body))
	for _, b := range body {
		if !contains(invalidChars, b) {
			cleanedBody = append(cleanedBody, b)
		}
	}

	return cleanedBody
}

// contains checks if a byte slice contains a specific byte.
func contains(slice []byte, b byte) bool {
	for _, item := range slice {
		if item == b {
			return true
		}
	}
	return false
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s Server) GetJWTData(r *http.Request) (JWTFields, error) {
	// find Authorization header
	header := r.Header.Get("Authorization")
	if header == "" {
		return JWTFields{}, errors.New("no Authorization header")
	}
	jwtTok := header[len("Bearer "):]
	godotenv.Load(FindEnv())
	token, err := jwt.Parse(jwtTok, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := errors.New("unexpected signing method")
			s.LogError(err, http.StatusInternalServerError)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_ENCRYPT_KEY")), nil
	})
	if err != nil {
		return JWTFields{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["exp"] == nil {
			return JWTFields{}, errors.New("invalid JWT, no expiration time given in claims")
		}
		if claims["exp"].(float64) < float64(time.Now().Unix()) {
			return JWTFields{}, errors.New("invalid JWT, token has expired")
		}
	} else {
		return JWTFields{}, errors.New("invalid JWT")
	}
	var fields JWTFields
	for key, value := range token.Claims.(jwt.MapClaims) {
		switch key {
		case JWTUUIDKey:
			fields.UUID = value.(string)
		case JWTExpiresKey:
			fields.Expires = int64(value.(float64))
		case JWTRoleKey:
			fields.Role = value.(string)
		case JWTStatusKey:
			fields.Status = value.(string)
		}
	}
	fields.Token = jwtTok
	return fields, nil
}

func FindEnv() string {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(exePath))), ".env")
}

func FindLatestOSMData() string {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(exePath))), "turkey-latest.osm.pbf")
}

const (
	SSLDisabled = "disable"
	SSLRequired = "require"
)

func GetPSQLConnString(isSSLDisabled string) string {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
		return ""
	}
	godotenv.Load(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(exePath))), ".psqlenv"))
	dbPort := os.Getenv("DB_PORT")
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	defaultDb := os.Getenv("DEFAULT_DB")
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPassword, dbHost, dbPort, defaultDb, isSSLDisabled)
}

type Restaurant struct {
	Name         string
	Cuisine      string
	OpeningHours string
	Phone        string
	Website      string
	Address      string
	Latitude     float64
	Longitude    float64
}

type Node struct {
	XMLName xml.Name `xml:"node"`
	Lat     float64  `xml:"lat,attr"`
	Lon     float64  `xml:"lon,attr"`
	Tags    []Tag    `xml:"tag"`
}

type Tag struct {
	XMLName xml.Name `xml:"tag"`
	Key     string   `xml:"k,attr"`
	Value   string   `xml:"v,attr"`
}

func fetchRestaurantsInArea(filename string, minLon, minLat, maxLon, maxLat float64) ([]Node, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := osmpbf.NewDecoder(file)
	err = decoder.Start(runtime.GOMAXPROCS(-1))
	if err != nil {
		return nil, err
	}

	var nodes []Node

	for {
		if v, err := decoder.Decode(); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else {
			switch v := v.(type) {
			case *osmpbf.Node:
				lat := v.Lat
				lon := v.Lon

				if lat >= minLat && lat <= maxLat && lon >= minLon && lon <= maxLon {
					amenity := v.Tags["amenity"]
					if amenity == "restaurant" {
						tags := make([]Tag, 0)
						for k, vv := range v.Tags {
							tags = append(tags, Tag{Key: k, Value: vv})
						}

						node := Node{
							Lat:  lat,
							Lon:  lon,
							Tags: tags,
						}

						nodes = append(nodes, node)
					}
				}
			}
		}
	}

	return nodes, nil
}
func FetchPlaces(db *pgxpool.Pool) {
	// Define bounding box coordinates for Istanbul
	fmt.Println("Fetching restaurant data...")
	var restaurants []Restaurant
	minLon := 28.8572
	minLat := 40.9382
	maxLon := 29.3487
	maxLat := 41.1283
	// Fetch restaurant nodes
	nodes, err := fetchRestaurantsInArea("./turkey-latest.osm.pbf", minLon, minLat, maxLon, maxLat)
	if err != nil {
		fmt.Println("Error fetching restaurant data:", err)
		return
	}

	// Process nodes and append to the restaurants slice
	for _, node := range nodes {
		name := extractTagValue(node.Tags, "name")
		if name != "" {
			cuisine := extractTagValue(node.Tags, "cuisine")
			openingHours := extractTagValue(node.Tags, "opening_hours")
			phone := extractTagValue(node.Tags, "phone")
			website := extractTagValue(node.Tags, "website")
			address := extractTagValue(node.Tags, "addr:full")

			restaurant := Restaurant{
				Name:         name,
				Cuisine:      cuisine,
				OpeningHours: openingHours,
				Phone:        phone,
				Website:      website,
				Address:      address,
				Latitude:     node.Lat,
				Longitude:    node.Lon,
			}

			restaurants = append(restaurants, restaurant)
		}
	}
	fmt.Printf("Fetched %d restaurants. \n", len(restaurants))
	// TODO: store the restaurant data in the postgres
}

func extractTagValue(tags []Tag, key string) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return ""
}
