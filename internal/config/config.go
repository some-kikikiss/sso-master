package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"time"
)

type Config struct {
	Env         string        `yaml:"env" env-default:"local"`
	StoragePath string        `yaml:"storage_path" env-required:"true"`
	TokenTTL    time.Duration `yaml:"token_ttl" env-default:"24h"`
	GRPC        GRPCConfig    `yaml:"grpc"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

// MustLoad loads the configuration from the specified path and returns it.
//
// It fetches the config path and checks if it's empty. If it is, it panics with
// an error message. Then it checks if the config file exists at the given path.
// If it doesn't, it panics with an error message.
//
// After that, it creates a Config struct variable and reads the config from the
// path using cleanenv.ReadConfig. If there's an error reading the config, it
// panics with an error message.
//
// Finally, it returns a pointer to the Config struct.
func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file not exist: " + path)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config:" + err.Error())

	}

	return &cfg
}

func MustLoadPath(configPath string) *Config {
	// check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}

	return &cfg
}

// fetchConfigPath fetch config path from command line or env variable;
// flag > env > default.
// Default is empty string.
func fetchConfigPath() string {
	var result string

	// --config="path/to/config.yaml"
	flag.StringVar(&result, "config", "", "config path")
	flag.Parse()

	if result == "" {
		result = os.Getenv("CONFIG_PATH")
	}

	return result
}
