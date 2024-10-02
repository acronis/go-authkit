/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"fmt"

	"github.com/acronis/go-appkit/config"
)

const (
	cfgKeyIDPURL          = "idp.url"
	cfgKeyIDPClientID     = "idp.clientId"
	cfgKeyIDPClientSecret = "idp.clientSecret"
)

// Config is a configuration for IDP token source.
type Config struct {
	URL          string
	ClientID     string
	ClientSecret string
}

var _ config.Config = (*Config)(nil)

// NewConfig creates a new configuration for IDP token source.
func NewConfig() *Config {
	return &Config{}
}

// SetProviderDefaults sets the default values for the configuration.
func (c *Config) SetProviderDefaults(_ config.DataProvider) {
}

// Set sets the configuration from the given data provider.
func (c *Config) Set(dp config.DataProvider) (err error) {
	if c.URL, err = dp.GetString(cfgKeyIDPURL); err != nil {
		return err
	}
	if c.URL == "" {
		return dp.WrapKeyErr(cfgKeyIDPURL, fmt.Errorf("IDP URL is required"))
	}
	if c.ClientID, err = dp.GetString(cfgKeyIDPClientID); err != nil {
		return err
	}
	if c.ClientID == "" {
		return dp.WrapKeyErr(cfgKeyIDPClientID, fmt.Errorf("IDP client ID is required"))
	}
	if c.ClientSecret, err = dp.GetString(cfgKeyIDPClientSecret); err != nil {
		return err
	}
	if c.ClientSecret == "" {
		return dp.WrapKeyErr(cfgKeyIDPClientSecret, fmt.Errorf("IDP client secret is required"))
	}

	return nil
}
