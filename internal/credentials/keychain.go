package credentials

import (
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

const serviceName = "qualys-mcp"

type Store interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

type KeychainStore struct{}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

func (k *KeychainStore) Get(key string) (string, error) {
	value, err := keyring.Get(serviceName, key)
	if err != nil {
		return "", fmt.Errorf("get %s from keychain: %w", key, err)
	}
	return value, nil
}

func (k *KeychainStore) Set(key, value string) error {
	if err := keyring.Set(serviceName, key, value); err != nil {
		return fmt.Errorf("set %s in keychain: %w", key, err)
	}
	return nil
}

func (k *KeychainStore) Delete(key string) error {
	if err := keyring.Delete(serviceName, key); err != nil {
		return fmt.Errorf("delete %s from keychain: %w", key, err)
	}
	return nil
}

type EnvStore struct {
	prefix string
}

func NewEnvStore(prefix string) *EnvStore {
	return &EnvStore{prefix: prefix}
}

func (e *EnvStore) Get(key string) (string, error) {
	envKey := e.prefix + key
	value := os.Getenv(envKey)
	if value == "" {
		return "", fmt.Errorf("environment variable %s not set", envKey)
	}
	return value, nil
}

func (e *EnvStore) Set(key, value string) error {
	return os.Setenv(e.prefix+key, value)
}

func (e *EnvStore) Delete(key string) error {
	return os.Unsetenv(e.prefix + key)
}

type ChainStore struct {
	stores []Store
}

func NewChainStore(stores ...Store) *ChainStore {
	return &ChainStore{stores: stores}
}

func (c *ChainStore) Get(key string) (string, error) {
	var lastErr error
	for _, store := range c.stores {
		value, err := store.Get(key)
		if err == nil {
			return value, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (c *ChainStore) Set(key, value string) error {
	if len(c.stores) == 0 {
		return fmt.Errorf("no stores configured")
	}
	return c.stores[0].Set(key, value)
}

func (c *ChainStore) Delete(key string) error {
	var lastErr error
	for _, store := range c.stores {
		if err := store.Delete(key); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

type Manager struct {
	store Store
}

func NewManager(store Store) *Manager {
	return &Manager{store: store}
}

func NewDefaultManager() *Manager {
	chain := NewChainStore(
		NewKeychainStore(),
		NewEnvStore("QUALYS_"),
	)
	return NewManager(chain)
}

func (m *Manager) GetUsername() (string, error) {
	return m.store.Get("USERNAME")
}

func (m *Manager) GetPassword() (string, error) {
	return m.store.Get("PASSWORD")
}

func (m *Manager) SetCredentials(username, password string) error {
	if err := m.store.Set("USERNAME", username); err != nil {
		return err
	}
	return m.store.Set("PASSWORD", password)
}

func (m *Manager) ClearCredentials() error {
	_ = m.store.Delete("USERNAME")
	_ = m.store.Delete("PASSWORD")
	return nil
}

func (m *Manager) Validate() error {
	username, err := m.GetUsername()
	if err != nil {
		return fmt.Errorf("username not configured: %w", err)
	}
	if username == "" {
		return fmt.Errorf("username is empty")
	}

	password, err := m.GetPassword()
	if err != nil {
		return fmt.Errorf("password not configured: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password is empty")
	}

	return nil
}
