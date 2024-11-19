// internal/service/otp.go

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"otp-service/internal/domain"
	"otp-service/pkg/logger"
	"otp-service/pkg/utils"
	"time"

	"github.com/google/uuid"
)

// internal/service/otp.go

type otpService struct {
	repo     domain.OTPRepository
	testMode bool
}

func NewOTPService(repo domain.OTPRepository, serverMode string) domain.OTPService {
	return &otpService{
		repo:     repo,
		testMode: serverMode == "test",
	}
}

func (s *otpService) Generate(ctx context.Context, req *domain.OTPRequest) (*domain.OTPResponse, error) {
	if err := utils.ValidateOTPRequest(req); err != nil {
		return nil, err
	}

	otp := &domain.OTP{
		UUID:             uuid.New().String(),
		Code:             utils.GenerateOTP(req.CodeLength, req.UseAlphaNumeric),
		TTL:              req.TTL,
		RetryLimit:       req.RetryLimit,
		StrictValidation: req.StrictValidation,
		UseAlphaNumeric:  req.UseAlphaNumeric,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Duration(req.TTL) * time.Second),
	}

	// Store original JSON if strict validation is enabled
	if req.StrictValidation && len(req.RawJSON) > 0 {
		otp.OriginalJSON = req.RawJSON
	}

	if err := s.repo.Store(ctx, otp); err != nil {
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	response := &domain.OTPResponse{
		Status:  http.StatusOK,
		Message: "OTP_GENERATED",
		Info: domain.OTPResponseInfo{
			UUID: otp.UUID,
		},
	}

	// Include OTP in response only in test mode
	if s.testMode {
		response.Info.OTP = otp.Code
	}

	return response, nil
}

func (s *otpService) Verify(ctx context.Context, req *domain.VerifyRequest) error {
	otp, err := s.repo.Get(ctx, req.UUID)
	if err != nil {
		return err
	}

	// Check expiration
	if time.Now().After(otp.ExpiresAt) {
		if err := s.repo.Delete(ctx, req.UUID); err != nil {
			// Log the error but don't return it to the client since verification was successful
			logger.Error(fmt.Sprintf("Failed to delete Expired OTP %s: %v", req.UUID, err))
		}
		return domain.ErrOTPExpired
	}

	// Check retry limit
	if otp.RetryCount >= otp.RetryLimit {
		if err := s.repo.Delete(ctx, req.UUID); err != nil {
			// Log the error but don't return it to the client since verification was successful
			logger.Error(fmt.Sprintf("Failed to delete Invalid Retry Attempts OTP %s: %v", req.UUID, err))
		}
		return domain.ErrOTPAttempts
	}

	// For strict validation, validate JSON payload
	if otp.StrictValidation {
		if len(otp.OriginalJSON) > 0 {
			// Must have request body when strict validation is enabled
			if len(req.StrictRequest) == 0 {
				otp.RetryCount++
				if err := s.repo.Update(ctx, otp); err != nil {
					return err
				}
				logger.Debug("Strict validation failed: No request body provided")
				return domain.ErrRequestBodyMismatch
			}

			// Normalize and compare JSONs
			originalJSON := normalizeJSON(otp.OriginalJSON)
			receivedJSON := normalizeJSON(req.StrictRequest)

			logger.Debug(fmt.Sprintf("Comparing JSONs:\nOriginal: %s\nReceived: %s",
				originalJSON, receivedJSON))

			if originalJSON != receivedJSON {
				otp.RetryCount++
				if err := s.repo.Update(ctx, otp); err != nil {
					return err
				}
				logger.Debug("Strict validation failed: JSON mismatch")
				return domain.ErrRequestBodyMismatch
			}
		}
	}

	// Verify OTP code
	if otp.Code != req.Code {
		otp.RetryCount++
		if err := s.repo.Update(ctx, otp); err != nil {
			return err
		}
		return domain.ErrOTPInvalid
	}

	// If we get here, verification was successful - Delete the OTP
	if err := s.repo.Delete(ctx, req.UUID); err != nil {
		// Log the error but don't return it to the client since verification was successful
		logger.Error(fmt.Sprintf("Failed to delete verified OTP %s: %v", req.UUID, err))
	} else {
		logger.Debug(fmt.Sprintf("Successfully deleted verified OTP %s", req.UUID))
	}

	return nil
}

// normalizeJSON removes whitespace but preserves case sensitivity
func normalizeJSON(data json.RawMessage) string {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		logger.Error("Failed to unmarshal JSON for normalization: ", err)
		return ""
	}

	normalized, err := json.Marshal(obj)
	if err != nil {
		logger.Error("Failed to marshal normalized JSON: ", err)
		return ""
	}

	return string(normalized)
}
