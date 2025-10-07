package rbac

import "context"

type Store interface {
	// Roles
	CreateRole(ctx context.Context, role Role) error
	GetRole(ctx context.Context, roleID string) (Role, error)
	UpdateRole(ctx context.Context, role Role) error
	RemoveRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context) ([]Role, error)

	// Permissions
	CreatePermission(ctx context.Context, p Permission) error
	GetPermission(ctx context.Context, id string) (Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	RemovePermission(ctx context.Context, id string) error

	// Subject role bindings
	AssignRole(ctx context.Context, subjectID, roleID string) error
	RevokeRole(ctx context.Context, subjectID, roleID string) error
	ListSubjects(ctx context.Context) ([]string, error)
	ListSubjectRoles(ctx context.Context, subjectID string) ([]Role, error)

	// Subject direct grants
	GrantSubject(ctx context.Context, subjectID string, g Grant) error
	RevokeSubjectGrant(ctx context.Context, subjectID string, grantID string) error
	ListSubjectGrants(ctx context.Context, subjectID string) ([]Grant, error)
}
