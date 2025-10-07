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
	)
}

type Role struct {
	ID          string       `gorm:"primaryKey"`
	Name        string       `gorm:"uniqueIndex;not null"`
	Description string       `gorm:"type:text"`
	ParentID    string       `gorm:"index;constraint:OnDelete:RESTRICT"`
	Parent      *Role        `gorm:"foreignKey:ParentID;references:ID"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
}

type Permission struct {
	ID       string `gorm:"primaryKey"`
	Resource string `gorm:"not null;index:idx_resource_action"`
	Action   string `gorm:"not null;index:idx_resource_action"`
	BizRule  string `gorm:"type:text"`
	Roles    []Role `gorm:"many2many:role_permissions;"`
}

type User struct {
	ID     string `gorm:"primaryKey"`
	RoleID string `gorm:"index"`
}
