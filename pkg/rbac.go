package rbac

import (
	"context"

	"github.com/google/uuid"
)

// RBAC is the main role-based access control manager
type RBAC struct {
	store    Store
	bizRules map[string]BizRule
}

// NewRBAC creates a new RBAC instance with the given store and optional configuration
func NewRBAC(ctx context.Context, s Store, opts ...Option) (*RBAC, error) {
	r := &RBAC{
		store:    s,
		bizRules: make(map[string]BizRule),
	}
	for _, opt := range opts {
		if err := opt(ctx, r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Option is a function that configures the RBAC instance during initialization
type Option func(ctx context.Context, r *RBAC) error

// WithSeed seeds the RBAC system with predefined roles
func WithSeed(roles []Role) Option {
	return func(ctx context.Context, r *RBAC) error {
		return r.initFromSeed(ctx, roles)
	}
}

func (r *RBAC) initFromSeed(ctx context.Context, roles []Role) error {
	for _, role := range roles {
		if err := r.store.CreateRole(ctx, role); err != nil {
			return err
		}
	}
	return nil
}

// CreateRole creates a new role with optional parent for hierarchy
func (r *RBAC) CreateRole(ctx context.Context, name, description string, parentName ...string) (Role, error) {
	n := normalizeString(name)
	if n == "" {
		return Role{}, ErrInvalidName
	}

	exists, err := r.roleNameExists(ctx, n)
	if err != nil {
		return Role{}, err
	}
	if exists {
		return Role{}, ErrDuplicateRole
	}

	role := Role{ID: uuid.New().String(), Name: n, Description: description}

	if len(parentName) > 0 && parentName[0] != "" {
		// Get parent role by name
		parent, err := r.store.GetRoleByName(ctx, parentName[0])
		if err != nil {
			return Role{}, ErrNotFound
		}

		role.ParentID = parent.ID
	}

	if err := r.store.CreateRole(ctx, role); err != nil {
		return Role{}, err
	}
	return role, nil
}

// UpdateRole updates an existing role's parent, which can be used to reorganize the hierarchy
func (r *RBAC) UpdateRole(ctx context.Context, roleName, newParentName string) error {
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}

	if newParentName != "" {
		parent, err := r.store.GetRoleByName(ctx, newParentName)
		if err != nil {
			return ErrNotFound
		}

		if err := r.checkRoleHierarchyCycle(ctx, parent.ID, role.ID); err != nil {
			return err
		}

		role.ParentID = parent.ID
	} else {
		role.ParentID = ""
	}

	return r.store.UpdateRole(ctx, role)
}

// RemoveRole deletes a role if it's not in use by any subject
func (r *RBAC) RemoveRole(ctx context.Context, roleName string) error {
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}

	inUse, err := r.isRoleInUse(ctx, role.ID)
	if err != nil {
		return err
	}
	if inUse {
		return ErrRoleInUse
	}

	return r.store.RemoveRole(ctx, role.ID)
}

// CreatePermission creates a new permission with optional business rule
func (r *RBAC) CreatePermission(ctx context.Context, resource, action string, bizRuleName ...string) (Permission, error) {
	res := normalizeString(resource)
	a := normalizeString(action)
	if res == "" || a == "" {
		return Permission{}, ErrInvalidResourceOrAction
	}

	bizRule := ""
	if len(bizRuleName) > 0 && bizRuleName[0] != "" {
		bizRule = bizRuleName[0]
	}

	exists, err := r.permissionExists(ctx, res, a, bizRule)
	if err != nil {
		return Permission{}, err
	}
	if exists {
		return Permission{}, ErrDuplicatePermission
	}

	p := Permission{ID: uuid.New().String(), Resource: res, Action: a, BizRule: bizRule}

	if err := r.store.CreatePermission(ctx, p); err != nil {
		return Permission{}, err
	}
	return p, nil
}

// RemovePermission deletes a permission if it's not assigned to any role
func (r *RBAC) RemovePermission(ctx context.Context, permID string) error {
	if err := validateUUIDs(permID); err != nil {
		return err
	}

	if _, err := r.store.GetPermission(ctx, permID); err != nil {
		return ErrNotFound
	}

	inUse, err := r.isPermissionInUse(ctx, permID)
	if err != nil {
		return err
	}
	if inUse {
		return ErrPermissionInUse
	}

	return r.store.RemovePermission(ctx, permID)
}

// CreateSubjectWithRole creates a new subject and assigns a role by role name
func (r *RBAC) CreateSubjectWithRole(ctx context.Context, subjectID, roleName string) error {
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}

	subject := Subject{
		ID:     subjectID,
		RoleID: role.ID,
	}
	return r.store.CreateSubject(ctx, subject)
}

// AssignRole assigns a role to a subject
func (r *RBAC) AssignRole(ctx context.Context, subjectID, roleName string) error {
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}

	subject, err := r.store.GetSubject(ctx, subjectID)
	if err != nil {
		return err
	}

	subject.RoleID = role.ID
	return r.store.UpdateSubject(ctx, subject)
}

// AddPermissionToRole adds a permission to a role
func (r *RBAC) AddPermissionToRole(ctx context.Context, roleName, permID string) error {
	if err := validateUUIDs(permID); err != nil {
		return err
	}
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}
	if roleHasPermission(&role, permID) {
		return ErrAlreadyExists
	}
	p, err := r.store.GetPermission(ctx, permID)
	if err != nil {
		return ErrNotFound
	}
	role.Permissions = append(role.Permissions, p)
	return r.store.UpdateRole(ctx, role)
}

// RemovePermissionFromRole removes a permission from a role
func (r *RBAC) RemovePermissionFromRole(ctx context.Context, roleName, permID string) error {
	if err := validateUUIDs(permID); err != nil {
		return err
	}
	role, err := r.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return ErrNotFound
	}

	if !roleHasPermission(&role, permID) {
		return ErrNotFound
	}

	role.Permissions = filterOutPermission(role.Permissions, permID)
	return r.store.UpdateRole(ctx, role)
}

// Can checks if a subject has permission to perform an action on a resource
func (r *RBAC) Can(ctx context.Context, subjectID, action string, resource Resource) (bool, error) {
	subject, err := r.store.GetSubject(ctx, subjectID)
	if err != nil {
		return false, err
	}

	if resource == nil {
		return false, ErrInvalidResourceOrAction
	}

	res := normalizeString(resource.Name())
	act := normalizeString(action)
	if res == "" || act == "" {
		return false, ErrInvalidResourceOrAction
	}

	if subject.RoleID == "" {
		return false, nil
	}

	// Validate roleID
	if err := validateUUIDs(subject.RoleID); err != nil {
		return false, err
	}

	role, err := r.store.GetRole(ctx, subject.RoleID)
	if err != nil {
		return false, err
	}

	return r.checkRolePermission(ctx, role, subjectID, act, resource)
}

func (r *RBAC) checkRolePermission(ctx context.Context, role Role, subjectID, action string, resourceObj Resource) (bool, error) {
	var hasPermission bool
	var permErr error

	err := r.traverseRoleHierarchy(ctx, role, func(currentRole Role) error {
		for _, p := range currentRole.Permissions {
			if p.Resource != resourceObj.Name() {
				continue
			}
			if p.Action != action {
				continue
			}

			if p.BizRule == "" {
				hasPermission = true
				return nil
			}

			rule, exists := r.GetBizRule(p.BizRule)
			if !exists {
				continue
			}

			allowed, err := rule.Evaluate(ctx, subjectID, resourceObj)
			if err != nil {
				permErr = err
				return err
			}

			if !allowed {
				continue
			}

			hasPermission = true
			return nil
		}
		return nil
	})

	if err != nil {
		if permErr != nil {
			return false, permErr
		}
		return false, err
	}

	return hasPermission, nil
}
