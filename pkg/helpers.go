package rbac

import (
	"strings"

	"github.com/google/uuid"
)

func normalizeString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func validateUUIDs(ids ...string) error {
	for _, id := range ids {
		if _, err := uuid.Parse(id); err != nil {
			return err
		}
	}
	return nil
}

func roleHasPermission(role *Role, permID string) bool {
	for _, p := range role.Permissions {
		if p.ID == permID {
			return true
		}
	}
	return false
}

func filterOutPermission(perms []Permission, permID string) []Permission {
	filtered := perms[:0]
	for _, p := range perms {
		if p.ID != permID {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
