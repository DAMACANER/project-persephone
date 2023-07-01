package core

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qedus/osmpbf"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"os"
	_ "persephone/docs"
	"runtime"
	"time"
)

func (s Server) LogError(err error, httpCode int) {
	// don`t log if middleware is not yet initialized
	reqID := middleware.GetReqID(s.Request.Context())
	traceback := make([]byte, 1<<16)
	runtime.Stack(traceback, true)
	headers := s.Request.Header
	jwtContents, errJWTData := s.GetJWTData()
	if errJWTData != nil {
		log.Printf("Error getting JWT data: %v", err)
	}
	jwtMarshal, errMarshalData := json.MarshalIndent(jwtContents, "", "    ")
	if errMarshalData != nil {
		log.Printf("Error marshaling JWT data: %v", err)
	}
	if s.Tracer != nil {
		s.Tracer.SetAttributes(attribute.KeyValue{
			Key: "reqID", Value: attribute.StringValue(reqID),
		})
		s.Tracer.SetAttributes(attribute.KeyValue{
			Key: "traceback", Value: attribute.StringValue(string(bytes.TrimSpace(bytes.TrimRight(traceback, "\x00")))),
		})
		s.Tracer.SetAttributes(attribute.KeyValue{
			Key: "headers", Value: attribute.StringValue(fmt.Sprintf("%v", headers)),
		})
		s.Tracer.SetAttributes(attribute.KeyValue{
			Key: "jwt", Value: attribute.StringValue(string(jwtMarshal)),
		})
		s.Tracer.SetStatus(codes.Error, err.Error())
		// record error
		s.Tracer.RecordError(err)
	}
	if s.Logger != nil {
		s.Logger.Error(err.Error(), reqID)
	}
	if s.Writer != nil {
		s.Writer.WriteHeader(httpCode)
		s.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		errMessageJSON, _ := json.MarshalIndent(ErrorResponse{Error: err.Error(), RequestID: reqID}, "", "    ")
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
	return true, nil
}

func (s Server) Bind(toMarshal interface{}) error {
	err := json.NewDecoder(s.Request.Body).Decode(&toMarshal)
	if err != nil {
		s.LogError(err, http.StatusBadRequest)
		return err
	}
	return nil
}

// GetUniqueUUID returns an unique UUID for a given table and field.
//
// Example:
//
//	userData.ID, err = s.GetUniqueUUID(UserTableName, IDDBField)
//
// Returns a new UUID that is unique in the table "users" table for the field "id".
func (s Server) GetUniqueUUID(tableName string, dbIDField string) (uuid.UUID, error) {
	for {
		var userID, err = uuid.NewUUID()
		if err != nil {
			return userID, err
		}
		// check if user exists with this id
		user := s.StmtBuilder.Select("*").From(tableName).Where(squirrel.Eq{dbIDField: userID.String()})
		sql, args, err := user.ToSql()
		if err != nil {
			return userID, err
		}
		to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rows, err := s.DB.Query(to, sql, args...)
		cancel()
		if err != nil {
			return userID, err
		}
		if rows.Next() {
			// try again
		} else {
			return userID, err
		}
	}
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

func (s Server) GetJWTData() (JWTFields, error) {
	// find Authorization header
	header := s.Request.Header.Get("Authorization")
	if header == "" {
		return JWTFields{}, errors.New("no Authorization header")
	}
	jwtTok := header[len("Bearer "):]
	token, err := jwt.Parse(jwtTok, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := errors.New("unexpected signing method")
			s.LogError(err, http.StatusInternalServerError)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWT_ENCRYPT_KEY), nil
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
			fields.Expires = value.(float64)
		case JWTRoleKey:
			fields.Role = value.(string)
		case JWTStatusKey:
			fields.Status = value.(string)
		}
	}
	fields.Token = jwtTok
	return fields, nil
}

func GetPSQLConnString(isSSLDisabled string) string {
	dbPort := DBPort
	dbHost := DBHost
	dbUser := DBUser
	dbPassword := DBPassword
	defaultDb := DefaultDB
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s", dbUser, dbPassword, dbHost, dbPort, defaultDb, isSSLDisabled)
}

func GetPgPool() (*pgxpool.Pool, error) {
	db, err := pgxpool.New(context.Background(), GetPSQLConnString(DBConnSSLDisabled))
	if err != nil {
		return nil, err
	}
	to, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// acquire a connection from the pool, just to test if it works
	conn, err := db.Acquire(to)
	if err != nil {
		return nil, err
	}
	if conn.Ping(to) != nil {
		return nil, err
	}
	conn.Release()
	return db, nil
}
func ReturnHandler() http.Handler {
	router := chi.NewRouter()
	//
	// PRE-SET MIDDLEWARES
	//
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	// please do not fiddle with middleware order.
	router.Use(AssignServer)
	router.Use(AssignWriter)
	router.Use(AssignRequest)
	router.Use(AssignLogger())
	router.Use(AssignValidator)
	router.Use(AssignQueryBuilder)

	//
	// POSTGRES CONNECTION POOL INITIALIZATION
	//
	db, err := GetPgPool()
	if err != nil {
		panic(err)
	}
	router.Use(AssignDB(db))
	// MOUNT YOUR ROUTERS HERE.
	router.Route("/api", func(r chi.Router) {
		r.Mount("/user", NewUserHandler())
		r.Mount("/world", NewCityHandler())
		r.Get("/swagger/*", httpSwagger.Handler(
			httpSwagger.URL("http://localhost:3000/api/swagger/doc.json"),
		))
	})
	return otelhttp.NewHandler(router, "server", otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
		return operation + " " + r.URL.Path
	}))
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println(err)
		}
	}(file)

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
func FetchPlaces() {
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
		log.Printf("error scheduling cron for fetching places: %v", err)
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
