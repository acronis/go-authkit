/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/vasayxtx/go-glob"
)

type TrustedIssuerURLMatcher func(issURL *url.URL) bool

type TrustedIssuerStore struct {
	mu                sync.RWMutex
	issuers           map[string]string
	issuerURLMatchers []TrustedIssuerURLMatcher
}

func NewTrustedIssuerStore() *TrustedIssuerStore {
	return &TrustedIssuerStore{
		issuers: make(map[string]string),
	}
}

func (s *TrustedIssuerStore) AddTrustedIssuer(issName, issURL string) {
	s.mu.Lock()
	s.issuers[issName] = issURL
	s.mu.Unlock()
}

func (s *TrustedIssuerStore) AddTrustedIssuerURL(issURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	urlMatcher, err := makeTrustedIssuerURLMatcher(issURL)
	if err != nil {
		return err
	}
	s.issuerURLMatchers = append(s.issuerURLMatchers, urlMatcher)
	return nil
}

func (s *TrustedIssuerStore) GetURLForIssuer(issuer string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if issuerURL, ok := s.issuers[issuer]; ok {
		return issuerURL, true
	}

	parsedIssURL, err := url.Parse(issuer)
	if err != nil {
		return "", false
	}
	for i := range s.issuerURLMatchers {
		if s.issuerURLMatchers[i](parsedIssURL) {
			return issuer, true
		}
	}

	return "", false
}

func makeTrustedIssuerURLMatcher(urlPattern string) (TrustedIssuerURLMatcher, error) {
	parsedURL, err := url.Parse(urlPattern)
	if err != nil {
		return nil, fmt.Errorf("parse issuer URL glob pattern: %w", err)
	}
	hostMatcher := glob.Compile(parsedURL.Host)
	return func(issURL *url.URL) bool {
		return hostMatcher(issURL.Host) &&
			parsedURL.Path == issURL.Path &&
			parsedURL.Scheme == issURL.Scheme &&
			parsedURL.RawQuery == issURL.RawQuery
	}, nil
}
