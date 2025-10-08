package rbac

import "context"

type roleVisitor func(role Role) error

func (r *RBAC) traverseRoleHierarchy(ctx context.Context, role Role, visitor roleVisitor) error {
	currentRole := role
	for {
		if err := visitor(currentRole); err != nil {
			return err
		}

		if currentRole.ParentID == "" {
			break
		}

		parentRole, err := r.store.GetRole(ctx, currentRole.ParentID)
		if err != nil {
			return err
		}

		currentRole = parentRole
	}

	return nil
}

func (r *RBAC) checkRoleHierarchyCycle(ctx context.Context, parentID, childID string) error {
	visited := make(map[string]bool)
	currentID := parentID

	for currentID != "" {
		if currentID == childID {
			return ErrRoleCycle
		}

		if visited[currentID] {
			return ErrRoleCycle
		}
		visited[currentID] = true

		role, err := r.store.GetRole(ctx, currentID)
		if err != nil {
			return err
		}

		currentID = role.ParentID
	}

	return nil
}
