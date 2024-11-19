// internal/service/otp.go

package service

import (
	"context"
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

	code := utils.GenerateOTP(req.CodeLength, req.UseAlphaNumeric)

	otp := &domain.OTP{
		UUID:             uuid.New().String(),
		Code:             code,
		TTL:              req.TTL,
		RetryLimit:       req.RetryLimit,
		StrictValidation: req.StrictValidation,
		UseAlphaNumeric:  req.UseAlphaNumeric,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Duration(req.TTL) * time.Second),
	}

	if err := s.repo.Store(ctx, otp); err != nil {
		logger.Error("Failed to store OTP in Redis: ", err)
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	response := &domain.OTPResponse{
		Status:  http.StatusOK,
		Message: "OTP_GENERATED",
		Info: struct {
			UUID string `json:"uuid,omitempty"`
			Code string `json:"code,omitempty"`
		}{
			UUID: otp.UUID,
		},
	}

	// Include OTP code only in test mode
	if s.testMode {
		response.Info.Code = otp.Code
		logger.Warn("Test Mode: OTP code included in response: ", otp.Code)
	}

	return response, nil
}

func (s *otpService) Verify(ctx context.Context, uuid string, code string) error {
	otp, err := s.repo.Get(ctx, uuid)
	if err != nil {
		return err
	}

	// Verify OTP
	if err := s.verifyOTP(otp, code); err != nil {
		return err
	}

	return nil
}

func (s *otpService) verifyOTP(otp *domain.OTP, code string) error {
	// Check expiration
	if time.Now().After(otp.ExpiresAt) {
		return domain.ErrOTPExpired
	}

	// Check retry limit
	if otp.RetryCount >= otp.RetryLimit {
		return domain.ErrOTPAttempts
	}

	// Verify code
	if otp.Code != code {
		otp.RetryCount++
		return domain.ErrOTPInvalid
	}

	return nil
}
