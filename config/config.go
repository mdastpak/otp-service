// config/config.go

package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Redis  RedisConfig  `mapstructure:"redis"`
	Server ServerConfig `mapstructure:"server"`
}

// config/config.go

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

func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, err
	}

	return config, nil
}
