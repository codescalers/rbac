# RBAC - Role-Based Access Control

This project implements a flexible and powerful Role-Based Access Control (RBAC) system for Go applications. It provides hierarchical role management, dynamic permission evaluation through business rules, and supports multiple storage backends.

## Installation

- To use the provided package:

  ```bash
  import "github.com/codescalers/rbac/pkg"
  ```

  First import the package in your Go file

- Then get the package by running this command in CLI:

  ```bash
  go get github.com/codescalers/rbac
  ```

- Initialize the RBAC system:

  ```go
  // Setup database
  db, _ := gorm.Open(sqlite.Open("rbac.db"), &gorm.Config{})
  store, _ := store.NewGormStore(db)

  // Create RBAC instance
  r, _ := rbac.NewRBAC(context.Background(), store)
  ```

## Usage

The RBAC system provides a simple and intuitive API for managing roles, permissions, and subjects. Here's how to use the main features:

### Example: Blog Access Control

```go
ctx := context.Background()

// 1. Create roles with hierarchy
userRole, _ := r.CreateRole(ctx, "user", "Regular user")
adminRole, _ := r.CreateRole(ctx, "admin", "Administrator", "user")

// 2. Create permissions
readPerm, _ := r.CreatePermission(ctx, "blog", "read")
writePerm, _ := r.CreatePermission(ctx, "blog", "write")
deletePerm, _ := r.CreatePermission(ctx, "blog", "delete")

// 3. Assign permissions to roles
r.AddPermissionToRole(ctx, "user", readPerm.ID)
r.AddPermissionToRole(ctx, "admin", writePerm.ID)
r.AddPermissionToRole(ctx, "admin", deletePerm.ID)

// 4. Create subjects with roles
r.CreateSubjectWithRole(ctx, "user-123", "user")
r.CreateSubjectWithRole(ctx, "admin-456", "admin")

// 5. Check permissions
type Blog struct {
    ID    string
    Title string
}

func (b Blog) Name() string { return "blog" }

blog := Blog{ID: "1", Title: "My Post"}

// User can read (has direct permission)
canRead, _ := r.Can(ctx, "user-123", "read", blog)
fmt.Println("User can read:", canRead) // true

// User cannot delete (doesn't have permission)
canDelete, _ := r.Can(ctx, "user-123", "delete", blog)
fmt.Println("User can delete:", canDelete) // false

// Admin can read (inherited from user role)
canRead, _ = r.Can(ctx, "admin-456", "read", blog)
fmt.Println("Admin can read:", canRead) // true

// Admin can delete (has direct permission)
canDelete, _ = r.Can(ctx, "admin-456", "delete", blog)
fmt.Println("Admin can delete:", canDelete) // true
```

### Using Business Rules

Business rules allow dynamic permission evaluation based on resource context (e.g., ownership):

```go
// Define a business rule
type OwnershipRule struct{}

func (r OwnershipRule) Name() string {
    return "ownership"
}

func (r OwnershipRule) Evaluate(ctx context.Context, subjectID string, resource rbac.Resource) (bool, error) {
    blog, ok := resource.(BlogPost)
    if !ok {
        return false, fmt.Errorf("expected BlogPost")
    }
    return blog.OwnerID == subjectID, nil
}

// Register the rule
r.RegisterBizRule(rbac.BizRule(OwnershipRule{}))

// Create permission with business rule
updateOwnPerm, _ := r.CreatePermission(ctx, "blog", "update", "ownership")

// Add to role
r.AddPermissionToRole(ctx, "user", updateOwnPerm.ID)

// Check permission
type BlogPost struct {
    ID      string
    Title   string
    OwnerID string
}

func (b BlogPost) Name() string { return "blog" }

myPost := BlogPost{ID: "1", Title: "My Post", OwnerID: "user-123"}
otherPost := BlogPost{ID: "2", Title: "Other Post", OwnerID: "user-789"}

// User can update their own post
canUpdate, _ := r.Can(ctx, "user-123", "update", myPost)
fmt.Println("Can update own post:", canUpdate) // true

// User cannot update others' posts
canUpdate, _ = r.Can(ctx, "user-123", "update", otherPost)
fmt.Println("Can update other post:", canUpdate) // false
```

### Role Hierarchy

Child roles automatically inherit all permissions from their parent roles:

```go
// Create hierarchy: viewer <- editor <- admin
viewer, _ := r.CreateRole(ctx, "viewer", "Can view content")
editor, _ := r.CreateRole(ctx, "editor", "Can edit content", "viewer")
admin, _ := r.CreateRole(ctx, "admin", "Full access", "editor")

// Assign permissions
readPerm, _ := r.CreatePermission(ctx, "document", "read")
editPerm, _ := r.CreatePermission(ctx, "document", "edit")
deletePerm, _ := r.CreatePermission(ctx, "document", "delete")

r.AddPermissionToRole(ctx, "viewer", readPerm.ID)
r.AddPermissionToRole(ctx, "editor", editPerm.ID)
r.AddPermissionToRole(ctx, "admin", deletePerm.ID)

// Create users
r.CreateSubjectWithRole(ctx, "user-1", "viewer")
r.CreateSubjectWithRole(ctx, "user-2", "editor")
r.CreateSubjectWithRole(ctx, "user-3", "admin")

// viewer: can only read
// editor: can read (inherited) + edit
// admin: can read (inherited) + edit (inherited) + delete
```

For detailed API documentation, see [API Reference](./docs/API.md).

## Storage Backends

The library includes comprehensive tests with over 45 test cases:

```bash
# Run all tests
go test ./pkg/... -v

# Run tests with coverage
go test ./pkg/... -cover
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
