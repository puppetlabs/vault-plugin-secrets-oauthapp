package persistence

import (
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type Managers struct {
	storage logical.Storage
	locks   []*locksutil.LockEntry
}

func (m *Managers) Config() *ConfigManager {
	return &ConfigManager{
		storage: m.storage,
		locks:   m.locks,
	}
}

func (m *Managers) AuthCode() *AuthCodeManager {
	return &AuthCodeManager{
		storage: m.storage,
		locks:   m.locks,
	}
}

func (m *Managers) ClientCreds() *ClientCredsManager {
	return &ClientCredsManager{
		storage: m.storage,
		locks:   m.locks,
	}
}

type Holder struct {
	locks []*locksutil.LockEntry
}

func (h *Holder) Managers(storage logical.Storage) *Managers {
	return &Managers{
		storage: storage,
		locks:   h.locks,
	}
}

func NewHolder() *Holder {
	return &Holder{
		locks: locksutil.CreateLocks(),
	}
}
