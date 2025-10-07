package store

import (
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) (*GormStore, error) {
	store := &GormStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *GormStore) migrate() error {
	return s.db.AutoMigrate(
		&Role{},
		&Permission{},
		&User{},
		&Grant{},
	)
}

type Role struct {
	ID          string       `gorm:"primaryKey"`
	Name        string       `gorm:"uniqueIndex;not null"`
	Description string       `gorm:"type:text"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
	Users       []User       `gorm:"many2many:user_roles;"`
}

type Permission struct {
	ID       string `gorm:"primaryKey"`
	Resource string `gorm:"not null;index:idx_resource_action"`
	Action   string `gorm:"not null;index:idx_resource_action"`
	Roles    []Role `gorm:"many2many:role_permissions;"`
}

type User struct {
	ID     string  `gorm:"primaryKey"`
	Roles  []Role  `gorm:"many2many:user_roles;"`
	Grants []Grant `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

type Grant struct {
	ID         string `gorm:"primaryKey"`
	UserID     string `gorm:"not null;index"`
	Resource   string `gorm:"not null"`
	Action     string `gorm:"not null"`
	ResourceID string `gorm:"not null"`
}
