package rbac

// Common RBAC errors
var (
	ErrAlreadyExists           = errorString("already exists")
	ErrInvalidResourceOrAction = errorString("invalid resource or action")
	ErrInvalidName             = errorString("invalid name")
	ErrNotFound                = errorString("not found")
	ErrRoleInUse               = errorString("role is in use and cannot be removed")
	ErrPermissionInUse         = errorString("permission is in use and cannot be removed")
	ErrDuplicateRole           = errorString("role with this name already exists")
	ErrDuplicatePermission     = errorString("permission with this resource and action already exists")
	ErrRoleCycle               = errorString("role hierarchy cycle detected")
	ErrRoleHasChildren         = errorString("role has child roles and cannot be removed")
)

type errorString string

func (e errorString) Error() string { return string(e) }
