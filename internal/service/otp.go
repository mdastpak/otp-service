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

type otpService struct {
	repo domain.OTPRepository
}

func NewOTPService(repo domain.OTPRepository) domain.OTPService {
	return &otpService{repo: repo}
}

func (s *otpService) Generate(ctx context.Context, req *domain.OTPRequest) (*domain.OTPResponse, error) {
	// Validate request using the validator
	if err := utils.ValidateOTPRequest(req); err != nil {
		logger.Error("Request validation failed: ", err)
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

	// Store OTP
	if err := s.repo.Store(ctx, otp); err != nil {
		logger.Error("Failed to store OTP: ", err)
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	return &domain.OTPResponse{
		Status:  http.StatusOK,
		Message: "OTP_GENERATED",
		Info: struct {
			UUID string `json:"uuid,omitempty"`
		}{
			UUID: otp.UUID,
		},
	}, nil
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
