package rbac

import "context"

// traverseRoleHierarchy walks up the role hierarchy from a given role to its ancestors,
// calling the callback function for each role encountered.
// The traversal stops when there are no more parent roles or when the callback returns an error.
func (r *RBAC) traverseRoleHierarchy(ctx context.Context, roleID string, callback func(role Role) error) error {
	currentID := roleID

	for currentID != "" {
		role, err := r.store.GetRole(ctx, currentID)
		if err != nil {
			return err
		}

		if err := callback(role); err != nil {
			return err
		}

		currentID = role.ParentID
	}

	return nil
}

// checkRoleHierarchyCycle detects if adding a parent-child relationship would create a cycle.
// It walks up from the proposed parent and checks if we encounter the proposed child,
// which would indicate a cycle.
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
