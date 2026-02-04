package auth

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "qualys-mcp"
)

type Keychain struct{}

func NewKeychain() *Keychain {
	return &Keychain{}
}

func (k *Keychain) SetCredentials(username, password string) error {
	if err := keyring.Set(serviceName, "username", username); err != nil {
		return fmt.Errorf("store username: %w", err)
	}
	if err := keyring.Set(serviceName, "password", password); err != nil {
		return fmt.Errorf("store password: %w", err)
	}
	return nil
}

func (k *Keychain) GetCredentials() (username, password string, err error) {
	username, err = keyring.Get(serviceName, "username")
	if err != nil {
		return "", "", fmt.Errorf("get username: %w", err)
	}
	password, err = keyring.Get(serviceName, "password")
	if err != nil {
		return "", "", fmt.Errorf("get password: %w", err)
	}
	return username, password, nil
}

func (k *Keychain) DeleteCredentials() error {
	_ = keyring.Delete(serviceName, "username")
	_ = keyring.Delete(serviceName, "password")
	return nil
}
