package store

import (
	"context"
	"fmt"

	rbac "github.com/codescalers/rbac/pkg"
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
		&Subject{},
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

type Subject struct {
	ID     string `gorm:"primaryKey"`
	RoleID string `gorm:"index"`
}

func (s *GormStore) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

func (s *GormStore) CreateRole(ctx context.Context, role rbac.Role) error {
	r := Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		ParentID:    role.ParentID,
	}

	r.Permissions = convertPermissionsFromRBAC(role.Permissions)

	return s.db.WithContext(ctx).Create(&r).Error
}

func (s *GormStore) GetRole(ctx context.Context, roleID string) (rbac.Role, error) {
	var r Role
	err := s.db.WithContext(ctx).Preload("Permissions").First(&r, "id = ?", roleID).Error
	if err != nil {
		return rbac.Role{}, err
	}

	role := rbac.Role{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		ParentID:    r.ParentID,
		Permissions: convertToRBACPermissions(r.Permissions),
	}

	return role, nil
}

func (s *GormStore) GetRoleByName(ctx context.Context, name string) (rbac.Role, error) {
	var r Role
	err := s.db.WithContext(ctx).Preload("Permissions").First(&r, "name = ?", name).Error
	if err != nil {
		return rbac.Role{}, err
	}

	role := rbac.Role{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		ParentID:    r.ParentID,
		Permissions: convertToRBACPermissions(r.Permissions),
	}

	return role, nil
}

func (s *GormStore) UpdateRole(ctx context.Context, role rbac.Role) error {
	var permIDs []string
	for _, p := range role.Permissions {
		permIDs = append(permIDs, p.ID)
	}

	var perms []Permission
	if len(permIDs) > 0 {
		if err := s.db.WithContext(ctx).Find(&perms, "id IN ?", permIDs).Error; err != nil {
			return err
		}
		if len(perms) != len(permIDs) {
			return fmt.Errorf("some permissions not found for IDs: %v", permIDs)
		}
	}

	r := Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		ParentID:    role.ParentID,
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&r).Association("Permissions").Replace(perms); err != nil {
			return err
		}
		return tx.Save(&r).Error
	})
}

func (s *GormStore) RemoveRole(ctx context.Context, roleID string) error {
	return s.db.WithContext(ctx).Delete(&Role{}, "id = ?", roleID).Error
}

func (s *GormStore) ListRoles(ctx context.Context) ([]rbac.Role, error) {
	var roles []Role
	err := s.db.WithContext(ctx).Preload("Permissions").Find(&roles).Error
	if err != nil {
		return nil, err
	}

	result := make([]rbac.Role, 0, len(roles))
	for _, r := range roles {
		role := rbac.Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			ParentID:    r.ParentID,
			Permissions: convertToRBACPermissions(r.Permissions),
		}
		result = append(result, role)
	}

	return result, nil
}

func (s *GormStore) CreatePermission(ctx context.Context, p rbac.Permission) error {
	perm := Permission{
		ID:       p.ID,
		Resource: p.Resource,
		Action:   p.Action,
		BizRule:  p.BizRule,
	}
	return s.db.WithContext(ctx).Create(&perm).Error
}

func (s *GormStore) GetPermission(ctx context.Context, id string) (rbac.Permission, error) {
	var permission Permission
	err := s.db.WithContext(ctx).First(&permission, "id = ?", id).Error
	if err != nil {
		return rbac.Permission{}, err
	}

	return rbac.Permission{
		ID:       permission.ID,
		Resource: permission.Resource,
		Action:   permission.Action,
		BizRule:  permission.BizRule,
	}, nil
}

func (s *GormStore) ListPermissions(ctx context.Context) ([]rbac.Permission, error) {
	var perms []Permission
	err := s.db.WithContext(ctx).Find(&perms).Error
	if err != nil {
		return nil, err
	}

	result := make([]rbac.Permission, 0, len(perms))
	for _, perm := range perms {
		result = append(result, rbac.Permission{
			ID:       perm.ID,
			Resource: perm.Resource,
			Action:   perm.Action,
			BizRule:  perm.BizRule,
		})
	}
	return result, nil
}

func (s *GormStore) RemovePermission(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&Permission{}, "id = ?", id).Error
}

func (s *GormStore) CreateSubject(ctx context.Context, subject rbac.Subject) error {
	sub := Subject{
		ID:     subject.ID,
		RoleID: subject.RoleID,
	}
	return s.db.WithContext(ctx).Create(&sub).Error
}

func (s *GormStore) GetSubject(ctx context.Context, subjectID string) (rbac.Subject, error) {
	var sub Subject
	err := s.db.WithContext(ctx).First(&sub, "id = ?", subjectID).Error
	if err != nil {
		return rbac.Subject{}, err
	}

	return rbac.Subject{
		ID:     sub.ID,
		RoleID: sub.RoleID,
	}, nil
}

func (s *GormStore) UpdateSubject(ctx context.Context, subject rbac.Subject) error {
	sub := Subject{
		ID:     subject.ID,
		RoleID: subject.RoleID,
	}
	return s.db.WithContext(ctx).Save(&sub).Error
}

func (s *GormStore) ListSubjects(ctx context.Context) ([]string, error) {
	var subjects []Subject
	err := s.db.WithContext(ctx).Find(&subjects).Error
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(subjects))
	for _, sub := range subjects {
		result = append(result, sub.ID)
	}

	return result, nil
}

func convertPermissionsFromRBAC(rbacPerms []rbac.Permission) []Permission {
	perms := make([]Permission, 0, len(rbacPerms))
	for _, p := range rbacPerms {
		perms = append(perms, Permission{
			ID:       p.ID,
			Resource: p.Resource,
			Action:   p.Action,
			BizRule:  p.BizRule,
		})
	}
	return perms
}

func convertToRBACPermissions(perms []Permission) []rbac.Permission {
	rbacPerms := make([]rbac.Permission, 0, len(perms))
	for _, p := range perms {
		rbacPerms = append(rbacPerms, rbac.Permission{
			ID:       p.ID,
			Resource: p.Resource,
			Action:   p.Action,
			BizRule:  p.BizRule,
		})
	}
	return rbacPerms
}
