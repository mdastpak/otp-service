// internal/repository/redis/otp.go

package redis // Changed from redis_repository to redis to match directory name

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"otp-service/internal/domain"
	"otp-service/pkg/utils"

	"github.com/go-redis/redis/v8"
)

type otpRepository struct {
	client *redis.Client
	prefix string
}

func NewOTPRepository(client *redis.Client, prefix string) domain.OTPRepository {
	return &otpRepository{
		client: client,
		prefix: prefix,
	}
}

func (r *otpRepository) Store(ctx context.Context, otp *domain.OTP) error {
	key := r.generateKey(otp.UUID)
	data, err := json.Marshal(otp)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	// Store with TTL
	ttl := time.Duration(otp.TTL) * time.Second
	return r.client.Set(ctx, key, data, ttl).Err()
}

func (r *otpRepository) Get(ctx context.Context, uuid string) (*domain.OTP, error) {
	key := r.generateKey(uuid)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrOTPNotFound
		}
		return nil, fmt.Errorf("failed to get OTP: %w", err)
	}

	var otp domain.OTP
	if err := json.Unmarshal(data, &otp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}

	return &otp, nil
}

func (r *otpRepository) Update(ctx context.Context, otp *domain.OTP) error {
	return r.Store(ctx, otp)
}

func (r *otpRepository) Delete(ctx context.Context, uuid string) error {
	key := r.generateKey(uuid)
	result := r.client.Del(ctx, key)
	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to delete OTP: %w", err)
	}

	if result.Val() == 0 {
		return domain.ErrOTPNotFound
	}

	return nil
}

func (r *otpRepository) generateKey(uuid string) string {
	return fmt.Sprintf("%s:%s", r.prefix, utils.HashString(uuid))
}
