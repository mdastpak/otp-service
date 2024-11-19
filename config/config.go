// config/config.go

package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Redis  RedisConfig  `mapstructure:"redis"`
	Server ServerConfig `mapstructure:"server"`
}

type RedisConfig struct {
	Host      string `mapstructure:"host"`
	Port      string `mapstructure:"port"`
	Password  string `mapstructure:"password"`
	DB        string `mapstructure:"db"`
	KeyPrefix string `mapstructure:"key_prefix"`
	Timeout   int    `mapstructure:"timeout"`
	HashKeys  bool   `mapstructure:"hash_keys"`
}

type ServerConfig struct {
	Host    string        `mapstructure:"host"`
	Port    string        `mapstructure:"port"`
	Mode    string        `mapstructure:"mode"`
	Timeout TimeoutConfig `mapstructure:"timeout"`
	TLS     TLSConfig     `mapstructure:"tls"`
}

type TimeoutConfig struct {
	Read       int `mapstructure:"read"`
	Write      int `mapstructure:"write"`
	Idle       int `mapstructure:"idle"`
	ReadHeader int `mapstructure:"read_header"`
}

type TLSConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	CertFile    string `mapstructure:"cert_file"`
	KeyFile     string `mapstructure:"key_file"`
	ClientCerts string `mapstructure:"client_certs"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Enable environment variables
	viper.AutomaticEnv()

	// Bind environment variables
	viper.BindEnv("redis.host", "REDIS_HOST")
	viper.BindEnv("redis.port", "REDIS_PORT")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("redis.db", "REDIS_DB")
	viper.BindEnv("redis.key_prefix", "REDIS_KEY_PREFIX")
	viper.BindEnv("redis.timeout", "REDIS_TIMEOUT")
	viper.BindEnv("redis.hash_keys", "REDIS_HASH_KEYS")

	viper.BindEnv("server.host", "SERVER_HOST")
	viper.BindEnv("server.port", "SERVER_PORT")
	viper.BindEnv("server.mode", "SERVER_MODE")

	// Server timeouts
	viper.BindEnv("server.timeout.read", "SERVER_TIMEOUT_READ")
	viper.BindEnv("server.timeout.write", "SERVER_TIMEOUT_WRITE")
	viper.BindEnv("server.timeout.idle", "SERVER_TIMEOUT_IDLE")
	viper.BindEnv("server.timeout.read_header", "SERVER_TIMEOUT_READ_HEADER")

	// TLS settings
	viper.BindEnv("server.tls.enabled", "TLS_ENABLED")
	viper.BindEnv("server.tls.cert_file", "TLS_CERT_FILE")
	viper.BindEnv("server.tls.key_file", "TLS_KEY_FILE")
	viper.BindEnv("server.tls.client_certs", "TLS_CLIENT_CERTS")

	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}
