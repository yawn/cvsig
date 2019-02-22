package config

import (
	"github.com/yawn/cvsig/log"
)

// Config is the central configuration struct of cvpn
type Config struct {
	Verbose bool
}

// Init will perform post config initializations and validations
func (c *Config) Init() error {

	if c.Verbose {
		log.Verbose = true
	}

	return nil

}
