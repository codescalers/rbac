package rbac

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type RBAC struct {
	store Store
}

func New(ctx context.Context, s Store, opts ...Option) (*RBAC, error) {
	r := &RBAC{store: s}
	for _, opt := range opts {
		if err := opt(ctx, r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

type Option func(ctx context.Context, r *RBAC) error

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

func (r *RBAC) CreateRole(ctx context.Context, name, description string) error {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ErrInvalidName
	}
	role := Role{ID: uuid.New().String(), Name: n, Description: description}
	return r.store.CreateRole(ctx, role)
}

func (r *RBAC) RemoveRole(ctx context.Context, roleID string) error {
	if err := validateUUIDs(roleID); err != nil {
		return err
	}
	return r.store.RemoveRole(ctx, roleID)
}

func (r *RBAC) CreatePermission(ctx context.Context, resource, action string) error {
	res := strings.ToLower(strings.TrimSpace(resource))
	a := strings.ToLower(strings.TrimSpace(action))
	if res == "" || a == "" {
		return ErrInvalidResourceOrAction
	}
	p := Permission{ID: uuid.New().String(), Resource: res, Action: a}
	return r.store.CreatePermission(ctx, p)
}

func (r *RBAC) RemovePermission(ctx context.Context, permID string) error {
	if err := validateUUIDs(permID); err != nil {
		return err
	}
	return r.store.RemovePermission(ctx, permID)
}

func (r *RBAC) AssignRole(ctx context.Context, subjectID, roleID string) error {
	if err := validateUUIDs(roleID); err != nil {
		return err
	}
	return r.store.AssignRole(ctx, subjectID, roleID)
}

func (r *RBAC) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	if err := validateUUIDs(roleID); err != nil {
		return err
	}
	return r.store.RevokeRole(ctx, subjectID, roleID)
}

func (r *RBAC) AddPermissionToRole(ctx context.Context, roleID, permID string) error {
	if err := validateUUIDs(roleID, permID); err != nil {
		return err
	}
	role, err := r.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	if r.roleHasPermission(&role, permID) {
		return ErrAlreadyExists
	}
	p, err := r.store.GetPermission(ctx, permID)
	if err != nil {
		return err
	}
	role.Permissions = append(role.Permissions, p)
	return r.store.UpdateRole(ctx, role)
}

func (r *RBAC) RemovePermissionFromRole(ctx context.Context, roleID, permID string) error {
	if err := validateUUIDs(roleID, permID); err != nil {
		return err
	}
	role, err := r.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	role.Permissions = r.filterOutPermission(role.Permissions, permID)
	return r.store.UpdateRole(ctx, role)
}

// Direct grants
func (r *RBAC) GrantSubject(ctx context.Context, subjectID string, resource, action, resourceID string) error {
	res := strings.ToLower(strings.TrimSpace(resource))
	act := strings.ToLower(strings.TrimSpace(action))
	if res == "" || act == "" {
		return ErrInvalidResourceOrAction
	}
	rid := strings.ToLower(strings.TrimSpace(resourceID))
	grant := Grant{ID: uuid.New().String(), Resource: res, Action: act, ResourceID: rid}
	return r.store.GrantSubject(ctx, subjectID, grant)
}

func (r *RBAC) RevokeSubjectGrant(ctx context.Context, subjectID, grantID string) error {
	if err := validateUUIDs(grantID); err != nil {
		return err
	}
	return r.store.RevokeSubjectGrant(ctx, subjectID, grantID)
}

func (r *RBAC) Can(ctx context.Context, subjectID, action, resource string, resourceID ...string) (bool, error) {
	grants, err := r.store.ListSubjectGrants(ctx, subjectID)
	if err != nil {
		return false, err
	}
	roles, err := r.store.ListSubjectRoles(ctx, subjectID)
	if err != nil {
		return false, err
	}

	id := ""
	if len(resourceID) > 0 && resourceID[0] != "" {
		id = resourceID[0]
	}
	res := strings.ToLower(strings.TrimSpace(resource))
	act := strings.ToLower(strings.TrimSpace(action))
	if res == "" || act == "" {
		return false, ErrInvalidResourceOrAction
	}

	//direct grants
	for _, g := range grants {
		if g.Resource != res {
			continue
		}
		if g.Action != act {
			continue
		}
		if g.ResourceID != id && g.ResourceID != "*" {
			continue
		}
		return true, nil
	}

	//role permissions
	for _, role := range roles {
		for _, p := range role.Permissions {
			if p.Resource != res {
				continue
			}
			if p.Action != act {
				continue
			}
			return true, nil
		}
	}

	return false, nil
}

func (r *RBAC) roleHasPermission(role *Role, permID string) bool {
	for _, p := range role.Permissions {
		if p.ID == permID {
			return true
		}
	}
	return false
}

func (r *RBAC) filterOutPermission(perms []Permission, permID string) []Permission {
	filtered := perms[:0]
	for _, p := range perms {
		if p.ID != permID {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func validateUUIDs(ids ...string) error {
	for _, id := range ids {
		if _, err := uuid.Parse(id); err != nil {
			return err
		}
	}
	return nil
}
