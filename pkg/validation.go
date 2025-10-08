package rbac

import "context"

func (r *RBAC) roleNameExists(ctx context.Context, name string) (bool, error) {
	roles, err := r.store.ListRoles(ctx)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (r *RBAC) permissionExists(ctx context.Context, resource, action, bizRule string) (bool, error) {
	perms, err := r.store.ListPermissions(ctx)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p.Resource != resource {
			continue
		}
		if p.Action != action {
			continue
		}
		if p.BizRule != bizRule {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (r *RBAC) isRoleInUse(ctx context.Context, roleID string) (bool, error) {
	subjects, err := r.store.ListSubjects(ctx)
	if err != nil {
		return false, err
	}
	for _, subjectID := range subjects {
		subject, err := r.store.GetSubject(ctx, subjectID)
		if err != nil {
			continue
		}
		if subject.RoleID == roleID {
			return true, nil
		}
	}
	return false, nil
}

func (r *RBAC) isPermissionInUse(ctx context.Context, permID string) (bool, error) {
	roles, err := r.store.ListRoles(ctx)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		for _, p := range role.Permissions {
			if p.ID == permID {
				return true, nil
			}
		}
	}
	return false, nil
}
