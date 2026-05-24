package config

import "time"

type Options struct {
	DB           string
	Log          string
	Addr         string
	CertsDir     string
	TemplatesDir string
	IPPFile      string
	ClientSubnet string
	AdminUser    string
	AdminPass    string
	SessionTTL   time.Duration
}
