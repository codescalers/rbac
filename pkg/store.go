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

	// Subjects
	GetSubject(ctx context.Context, subjectID string) (User, error)
	UpdateSubject(ctx context.Context, user User) error
	ListSubjects(ctx context.Context) ([]string, error)
	ListSubjectRoles(ctx context.Context, subjectID string) ([]Role, error)
}
