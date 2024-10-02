package idptest

import (
	"context"
	"sync/atomic"
)

type SimpleTokenProvider struct {
	token atomic.Value
}

func NewSimpleTokenProvider(token string) *SimpleTokenProvider {
	tp := &SimpleTokenProvider{}
	tp.SetToken(token)
	return tp
}

func (m *SimpleTokenProvider) GetToken(ctx context.Context, scope ...string) (string, error) {
	return m.token.Load().(string), nil
}

func (m *SimpleTokenProvider) Invalidate() {}

func (m *SimpleTokenProvider) SetToken(token string) {
	m.token.Store(token)
}
