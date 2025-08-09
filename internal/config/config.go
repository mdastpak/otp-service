package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config structure to hold server, redis, and general configurations
type Config struct {
	Redis struct {
		Host      string `mapstructure:"host"`
		Port      string `mapstructure:"port"`
		Password  string `mapstructure:"password"`
		Indices   string `mapstructure:"indices"`
		KeyPrefix string `mapstructure:"key_prefix"`
		Timeout   int    `mapstructure:"timeout"`
	} `mapstructure:"redis"`
	Server struct {
		Host    string `mapstructure:"host"`
		Port    string `mapstructure:"port"`
		Mode    string `mapstructure:"mode"`
		Timeout struct {
			Read       int `mapstructure:"read"`
			Write      int `mapstructure:"write"`
			Idle       int `mapstructure:"idle"`
			ReadHeader int `mapstructure:"read_header"`
		}
		TLS struct {
			Enabled     bool   `mapstructure:"enabled"`
			CertFile    string `mapstructure:"cert_file"`
			KeyFile     string `mapstructure:"key_file"`
			ClientCerts string `mapstructure:"client_certs"`
		} `mapstructure:"tls"`
	} `mapstructure:"server"`
	Config struct {
		HashKeys bool `mapstructure:"hash_keys"`
	} `mapstructure:"config"`
	OTP struct {
		Length          int    `mapstructure:"length"`
		Expiry          string `mapstructure:"expiry"`
		MaxAttempts     int    `mapstructure:"max_attempts"`
		CleanupInterval string `mapstructure:"cleanup_interval"`
	} `mapstructure:"otp"`
	CORS struct {
		AllowedOrigins   string `mapstructure:"allowed_origins"`
		AllowedMethods   string `mapstructure:"allowed_methods"`
		AllowedHeaders   string `mapstructure:"allowed_headers"`
		ExposedHeaders   string `mapstructure:"exposed_headers"`
		MaxAge           string `mapstructure:"max_age"`
		AllowCredentials string `mapstructure:"allow_credentials"`
	} `mapstructure:"cors"`
	Security struct {
		HeadersEnabled bool   `mapstructure:"headers_enabled"`
		HSTSMaxAge     string `mapstructure:"hsts_max_age"`
		CSPPolicy      string `mapstructure:"csp_policy"`
	} `mapstructure:"security"`
}

// LoadConfig reads the configuration from the config file and environment variables
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	viper.AutomaticEnv()

	// Bind environment variables to specific keys in the config
	viper.BindEnv("redis.host", "REDIS_HOST")
	viper.BindEnv("redis.port", "REDIS_PORT")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("redis.indices", "REDIS_INDICES")
	viper.BindEnv("redis.key_prefix", "REDIS_KEY_PREFIX")
	viper.BindEnv("redis.timeout", "REDIS_TIMEOUT")
	viper.BindEnv("server.host", "SERVER_HOST")
	viper.BindEnv("server.port", "SERVER_PORT")
	viper.BindEnv("server.mode", "SERVER_MODE")
	viper.BindEnv("server.timeout.read", "SERVER_TIMEOUT_READ")
	viper.BindEnv("server.timeout.write", "SERVER_TIMEOUT_WRITE")
	viper.BindEnv("server.timeout.idle", "SERVER_TIMEOUT_IDLE")
	viper.BindEnv("server.timeout.read_header", "SERVER_TIMEOUT_READ_HEADER")
	viper.BindEnv("server.tls.enabled", "TLS_ENABLED")
	viper.BindEnv("server.tls.cert_file", "TLS_CERT_FILE")
	viper.BindEnv("server.tls.key_file", "TLS_KEY_FILE")
	viper.BindEnv("server.tls.client_certs", "TLS_CLIENT_CERTS")
	viper.BindEnv("config.hash_keys", "HASH_KEYS")
	viper.BindEnv("otp.length", "OTP_LENGTH")
	viper.BindEnv("otp.expiry", "OTP_EXPIRY")
	viper.BindEnv("otp.max_attempts", "OTP_MAX_ATTEMPTS")
	viper.BindEnv("otp.cleanup_interval", "OTP_CLEANUP_INTERVAL")
	viper.BindEnv("cors.allowed_origins", "CORS_ALLOWED_ORIGINS")
	viper.BindEnv("cors.allowed_methods", "CORS_ALLOWED_METHODS")
	viper.BindEnv("cors.allowed_headers", "CORS_ALLOWED_HEADERS")
	viper.BindEnv("cors.exposed_headers", "CORS_EXPOSED_HEADERS")
	viper.BindEnv("cors.max_age", "CORS_MAX_AGE")
	viper.BindEnv("cors.allow_credentials", "CORS_ALLOW_CREDENTIALS")
	viper.BindEnv("security.headers_enabled", "SECURITY_HEADERS_ENABLED")
	viper.BindEnv("security.hsts_max_age", "HSTS_MAX_AGE")
	viper.BindEnv("security.csp_policy", "CSP_POLICY")

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SetupLogger configures the logger based on server mode
func SetupLogger(mode string) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	if mode != "release" {
		logger.SetLevel(logrus.TraceLevel)
	}

	return logger
}
