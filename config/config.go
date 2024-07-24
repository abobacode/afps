package config

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"
)

type Server struct {
	FairPlay FairPlay `yaml:"fairplay"`
}

type FairPlay struct {
	Certificate string `yaml:"certificate"`
	Private     string `yaml:"private"`
	Ask         string `yaml:"ask"`
}

type Config struct {
	Server `yaml:"server"`
}

func New(filepath string) (*Config, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	d := yaml.NewDecoder(bytes.NewReader(content))
	if err = d.Decode(&config); err != nil {
		return nil, err
	}
	return config, nil
}
