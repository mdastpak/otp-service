package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var ctx = context.Background()

// Initialize Redis client
var redisClient = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // Redis password (if any)
	DB:       0,  // Default database
})

// OTPRequest structure for storing OTP-related info
type OTPRequest struct {
	OTP              string          `json:"otp"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	ExpirationTime   time.Time       `json:"expiration_time"`
	CodeLength       int             `json:"code_length"`
	StrictValidation bool            `json:"strict_validation"`
	UserData         json.RawMessage `json:"user_data"`
}

// Helper to send JSON error responses
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	http.Error(w, fmt.Sprintf(`{"error": "%s"}`, message), statusCode)
}

// Helper to retrieve and validate int query params
func getIntQueryParam(query url.Values, key string, defaultValue, min, max int) (int, error) {
	strVal := query.Get(key)
	if strVal == "" {
		return defaultValue, nil
	}
	intVal, err := strconv.Atoi(strVal)
	if err != nil || intVal < min || intVal > max {
		return 0, fmt.Errorf("invalid %s value: %v", key, strVal)
	}
	return intVal, nil
}

// Helper to retrieve and validate boolean query params
func getBoolQueryParam(query url.Values, key string, defaultValue bool) (bool, error) {
	strVal := query.Get(key)
	if strVal == "" {
		return defaultValue, nil
	}
	boolVal, err := strconv.ParseBool(strVal)
	if err != nil {
		return false, fmt.Errorf("invalid %s value: %v", key, strVal)
	}
	return boolVal, nil
}

// Generate OTP code based on length and complexity
func generateOTP(codeLength int, useAlphaNumeric bool) (string, error) {
	var charSet string
	if useAlphaNumeric {
		charSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	} else {
		charSet = "0123456789"
	}

	otpCode := make([]byte, codeLength)
	for i := 0; i < codeLength; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", err
		}
		otpCode[i] = charSet[num.Int64()]
	}
	return string(otpCode), nil
}

// Save OTP data to Redis
func saveOTPToRedis(requestUUID string, otpData OTPRequest) error {
	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	ttl, err := redisClient.TTL(ctx, requestUUID).Result()
	if err != nil || ttl <= 0 {
		ttl = time.Duration(otpData.TTL) * time.Second
	}

	return redisClient.Set(ctx, requestUUID, otpJSON, ttl).Err()
}

// Handle POST request to generate OTP
func generateOTPHandler(w http.ResponseWriter, r *http.Request) {
	var otpRequest OTPRequest
	w.Header().Set("Content-Type", "application/json")

	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		sendErrorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse the JSON
	if err := json.Unmarshal(bodyBytes, &otpRequest); err != nil {
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Store the valid JSON in UserData
	otpRequest.UserData = json.RawMessage(bodyBytes)

	// Query string parsing
	query := r.URL.Query()

	// Validate and set parameters
	if otpRequest.TTL, err = getIntQueryParam(query, "ttl", 60, 1, 3600); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if otpRequest.RetryLimit, err = getIntQueryParam(query, "retry_limit", 5, 1, 60); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if otpRequest.CodeLength, err = getIntQueryParam(query, "code_length", 6, 1, 10); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if otpRequest.TTL < otpRequest.RetryLimit {
		sendErrorResponse(w, "Retry limit must be less than or equal to TTL", http.StatusBadRequest)
		return
	}

	// Fetch boolean parameters
	if otpRequest.StrictValidation, err = getBoolQueryParam(query, "strict_validation", false); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if otpRequest.UseAlphaNumeric, err = getBoolQueryParam(query, "use_alpha_numeric", false); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate OTP
	if otpRequest.OTP, err = generateOTP(otpRequest.CodeLength, otpRequest.UseAlphaNumeric); err != nil {
		sendErrorResponse(w, "Error generating OTP", http.StatusInternalServerError)
		return
	}
	otpRequest.ExpirationTime = time.Now().Add(time.Duration(otpRequest.TTL) * time.Second)

	// Generate UUID and save OTP to Redis
	requestUUID := uuid.New().String()
	if err := saveOTPToRedis(requestUUID, otpRequest); err != nil {
		sendErrorResponse(w, "Error saving OTP to Redis", http.StatusInternalServerError)
		return
	}

	// Send response with generated UUID
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "OTP generated and sent",
		"uuid":    requestUUID,
	})
}

// Handle POST request to verify OTP
func verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query()
	requestUUID := query.Get("uuid")
	userInputOTP := query.Get("otp")

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		sendErrorResponse(w, "Missing UUID or OTP", http.StatusBadRequest)
		return
	}

	// Fetch OTP from Redis
	storedData, err := redisClient.Get(ctx, requestUUID).Result()
	if err != nil {
		sendErrorResponse(w, "OTP expired or not found", http.StatusUnauthorized)
		return
	}

	var otpData OTPRequest
	if err := json.Unmarshal([]byte(storedData), &otpData); err != nil {
		sendErrorResponse(w, "Error processing stored data", http.StatusInternalServerError)
		return
	}

	// Check if OTP has expired
	if time.Now().After(otpData.ExpirationTime) {
		redisClient.Del(ctx, requestUUID)
		sendErrorResponse(w, "OTP expired", http.StatusUnauthorized)
		return
	}

	// Check retry limit
	if otpData.RetryLimit <= 0 {
		redisClient.Del(ctx, requestUUID)
		sendErrorResponse(w, "Too many attempts, OTP invalidated", http.StatusUnauthorized)
		return
	}

	// Get remaining TTL from Redis
	ttl, err := redisClient.TTL(ctx, requestUUID).Result()
	if err != nil || ttl <= 0 {
		sendErrorResponse(w, "Error updating retry limit", http.StatusInternalServerError)
		return
	}

	// Check OTP case-insensitively if alphanumeric
	if !strings.EqualFold(otpData.OTP, userInputOTP) {
		otpData.RetryLimit--
		saveOTPToRedis(requestUUID, otpData)
		sendErrorResponse(w, "OTP mismatch", http.StatusUnauthorized)
		return
	}

	// Full body validation, if strict validation is enabled
	if otpData.StrictValidation {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			sendErrorResponse(w, "Invalid request", http.StatusBadRequest)
			return
		}

		var storedDataMap, currentDataMap map[string]interface{}
		if err := json.Unmarshal(otpData.UserData, &storedDataMap); err != nil {
			sendErrorResponse(w, "Error processing stored data", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(bodyBytes, &currentDataMap); err != nil {
			sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}
		if !reflect.DeepEqual(storedDataMap, currentDataMap) {
			sendErrorResponse(w, "Request body mismatch", http.StatusUnauthorized)
			return
		}
	}

	// OTP verified successfully, delete it from Redis
	redisClient.Del(ctx, requestUUID)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "OTP verified successfully",
	})
}

func main() {
	r := mux.NewRouter()

	// Register routes
	r.HandleFunc("/otp", generateOTPHandler).Methods("POST")
	r.HandleFunc("/otp", verifyOTPHandler).Methods("GET")

	log.Println("Server started at :8080")
	http.ListenAndServe(":8080", r)
}
