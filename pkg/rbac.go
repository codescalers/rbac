package rbac

import (
	"context"
	"strings"
)

type RBAC struct {
	store Store
}

func New(s Store) *RBAC {
	return &RBAC{store: s}
}

func (r *RBAC) CreateRole(ctx context.Context, role Role) error {
	role.Name = strings.ToLower(role.Name)
	return r.store.CreateRole(ctx, role)
}

func (r *RBAC) RemoveRole(ctx context.Context, roleID string) error {
	return r.store.RemoveRole(ctx, roleID)
}

func (r *RBAC) CreatePermission(ctx context.Context, p Permission) error {
	p.Resource = strings.ToLower(p.Resource)
	p.Action = strings.ToLower(p.Action)
	return r.store.CreatePermission(ctx, p)
}

func (r *RBAC) RemovePermission(ctx context.Context, id string) error {
	return r.store.RemovePermission(ctx, id)
}

func (r *RBAC) AssignRole(ctx context.Context, subjectID, roleID string) error {
	return r.store.AssignRole(ctx, subjectID, roleID)
}

func (r *RBAC) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	return r.store.RevokeRole(ctx, subjectID, roleID)
}

func (r *RBAC) AddPermissionToRole(ctx context.Context, roleID string, permID string) error {
	role, err := r.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	for _, p := range role.Permissions {
		if p.ID == permID {
			return ErrAlreadyExists
		}
	}
	p, err := r.store.GetPermission(ctx, permID)
	if err != nil {
		return err
	}
	role.Permissions = append(role.Permissions, p)
	return r.store.UpdateRole(ctx, role)
}

func (r *RBAC) RemovePermissionFromRole(ctx context.Context, roleID string, permID string) error {
	role, err := r.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	filtered := role.Permissions[:0]
	for _, p := range role.Permissions {
		if p.ID != permID {
			filtered = append(filtered, p)
		}

	}
	role.Permissions = filtered
	return r.store.UpdateRole(ctx, role)
}

// Direct grants
func (r *RBAC) GrantSubject(ctx context.Context, subjectID string, grant Grant) error {

	grant.Resource = strings.ToLower(grant.Resource)
	grant.Action = strings.ToLower(grant.Action)
	return r.store.GrantSubject(ctx, subjectID, grant)
}

func (r *RBAC) RevokeSubjectGrant(ctx context.Context, subjectID, grantID string) error {
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
	if len(resourceID) > 0 {
		id = resourceID[0]
	}
	res := strings.ToLower(resource)
	act := strings.ToLower(action)

	//direct grants
	for _, g := range grants {
		if strings.ToLower(g.Resource) != res {
			continue
		}
		if strings.ToLower(g.Action) != act {
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
			if strings.ToLower(p.Resource) != res {
				continue
			}
			if strings.ToLower(p.Action) != act {
				continue
			}
			return true, nil
		}
	}

	return false, nil
}
