package notari

import "sync"

type UserInfo struct {
	Sub      string
	Username string
	Keys     []Key
	Claims   map[string]interface{}
}

type Key struct {
	Key         string
	Fingerprint string
}

type Provider interface {
	GetUserInfo(name string) (*UserInfo, error)
}

type CachingProvider struct {
	inner Provider
	cache map[string]*UserInfo
	mutex sync.Mutex
}

func NewCachingProvider(inner Provider) Provider {
	return &CachingProvider{inner: inner, cache: make(map[string]*UserInfo)}
}

func (provider *CachingProvider) GetUserInfo(name string) (*UserInfo, error) {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()

	userInfo := provider.cache[name]
	if userInfo != nil {
		return userInfo, nil
	}

	userInfo, err := provider.inner.GetUserInfo(name)
	if err != nil {
		return nil, err
	}
	provider.cache[name] = userInfo
	return userInfo, nil
}
