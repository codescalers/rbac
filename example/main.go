package main

import (
	"context"
	"fmt"
	"log"

	rbac "github.com/codescalers/rbac/pkg"
	"github.com/codescalers/rbac/pkg/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Blog represents a blog post resource
type Blog struct {
	ID      string
	Title   string
	Content string
	OwnerID string
}

// Name implements the rbac.Resource interface
func (b Blog) Name() string {
	return "blog"
}

// BlogOwnershipRule ensures users can only access their own blogs
type BlogOwnershipRule struct{}

func (r BlogOwnershipRule) Name() string {
	return "blog_ownership"
}

func (r BlogOwnershipRule) Evaluate(ctx context.Context, subjectID string, resource rbac.Resource) (bool, error) {
	blog, ok := resource.(Blog)
	if !ok {
		return false, fmt.Errorf("expected Blog resource, got %T", resource)
	}

	// Allow access if the user is the owner
	return blog.OwnerID == subjectID, nil
}

func main() {
	ctx := context.Background()

	// Initialize SQLite database
	db, err := gorm.Open(sqlite.Open("rbac.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Create GORM store
	gormStore, err := store.NewGormStore(db)
	if err != nil {
		log.Fatal("Failed to create store:", err)
	}

	// Initialize RBAC
	r, err := rbac.NewRBAC(ctx, gormStore)
	if err != nil {
		log.Fatal(err)
	}

	// Register business rule for blog ownership
	bizRole := rbac.BizRule(BlogOwnershipRule{})
	if err := r.RegisterBizRule(bizRole); err != nil {
		log.Fatal(err)
	}

	// Create permissions
	readPerm, err := r.CreatePermission(ctx, "blog", "read")
	if err != nil {
		log.Fatal(err)
	}
	updateOwnPerm, err := r.CreatePermission(ctx, "blog", "update", bizRole.Name())
	if err != nil {
		log.Fatal(err)
	}
	deleteOwnPerm, err := r.CreatePermission(ctx, "blog", "delete", bizRole.Name())
	if err != nil {
		log.Fatal(err)
	}
	createPerm, err := r.CreatePermission(ctx, "blog", "create")
	if err != nil {
		log.Fatal(err)
	}

	updateAll, err := r.CreatePermission(ctx, "blog", "update")
	if err != nil {
		log.Fatal(err)
	}
	deleteAll, err := r.CreatePermission(ctx, "blog", "delete")
	if err != nil {
		log.Fatal(err)
	}

	// Create roles
	userRole, err := r.CreateRole(ctx, "user", "Regular user with blog access")
	if err != nil {
		log.Fatal(err)
	}
	adminRole, err := r.CreateRole(ctx, "admin", "Administrator with full access", userRole.ID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created roles: user=%s, admin=%s\n", userRole.ID, adminRole.ID)

	//Add user permissions
	if err := r.AddPermissionToRole(ctx, "user", readPerm.ID); err != nil {
		log.Fatal(err)
	}
	if err := r.AddPermissionToRole(ctx, "user", createPerm.ID); err != nil {
		log.Fatal(err)
	}
	if err := r.AddPermissionToRole(ctx, "user", updateOwnPerm.ID); err != nil {
		log.Fatal(err)
	}
	if err := r.AddPermissionToRole(ctx, "user", deleteOwnPerm.ID); err != nil {
		log.Fatal(err)
	}

	//Add admin permissions
	if err := r.AddPermissionToRole(ctx, "admin", updateAll.ID); err != nil {
		log.Fatal(err)
	}
	if err := r.AddPermissionToRole(ctx, "admin", deleteAll.ID); err != nil {
		log.Fatal(err)
	}

	// Create test users
	adminUserID := "admin-user-123"
	regularUserID := "regular-user-456"

	// Create subjects with roles using role names
	if err := r.CreateSubjectWithRole(ctx, adminUserID, "admin"); err != nil {
		log.Fatal(err)
	}
	if err := r.CreateSubjectWithRole(ctx, regularUserID, "user"); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Created subjects with roles")

	// Test blogs
	blog1 := Blog{ID: "blog-1", Title: "Admin's Blog", OwnerID: adminUserID}
	blog2 := Blog{ID: "blog-2", Title: "User's Blog", OwnerID: regularUserID}

	hasPerm, err := r.Can(ctx, regularUserID, "update", blog2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User has permission to update blog2: %v\n", hasPerm)
	hasPerm, err = r.Can(ctx, regularUserID, "update", blog1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User has permission to update blog1: %v\n", hasPerm)

	hasPerm, err = r.Can(ctx, adminUserID, "update", blog1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Admin has permission to update blog1: %v\n", hasPerm)
	hasPerm, err = r.Can(ctx, adminUserID, "update", blog2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Admin has permission to update blog2: %v\n", hasPerm)
}
