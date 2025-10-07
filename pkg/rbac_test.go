package rbac_test

import (
	"context"
	"testing"

	"github.com/codescalers/rbac/internal/mocks"
	rbac "github.com/codescalers/rbac/pkg"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewRBAC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)
	t.Run("Create new RBAC instance", func(t *testing.T) {
		r, err := rbac.NewRBAC(ctx, store)

		assert.NoError(t, err)
		assert.NotNil(t, r)
	})
	t.Run("Create new RBAC instance with seed", func(t *testing.T) {
		roles := []rbac.Role{
			{ID: "1", Name: "admin", Permissions: []rbac.Permission{{ID: "p1", Resource: "blog", Action: "read"}}},
			{ID: "2", Name: "user", Permissions: []rbac.Permission{{ID: "p2", Resource: "blog", Action: "update"}}},
		}
		store.EXPECT().CreateRole(ctx, roles[0]).Return(nil)
		store.EXPECT().CreateRole(ctx, roles[1]).Return(nil)

		r, err := rbac.NewRBAC(ctx, store, rbac.WithSeed(roles))

		assert.NoError(t, err)
		assert.NotNil(t, r)
	})
}

func TestCreateRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)
	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	adminID := "550e8400-e29b-41d4-a716-446655440000"
	existingAdmin := rbac.Role{ID: adminID, Name: "admin"}

	store.EXPECT().ListRoles(ctx).Return([]rbac.Role{existingAdmin}, nil).Times(4)
	store.EXPECT().GetRole(ctx, adminID).Return(rbac.Role{ID: adminID, Name: "admin"}, nil).Times(1)
	store.EXPECT().CreateRole(ctx, gomock.Any()).Return(nil).Times(2)

	t.Run("Create role with empty name", func(t *testing.T) {
		_, err := r.CreateRole(ctx, "", "description")
		assert.ErrorIs(t, err, rbac.ErrInvalidName)
	})

	t.Run("Create role with duplicate name", func(t *testing.T) {
		_, err := r.CreateRole(ctx, "admin", "description")
		assert.ErrorIs(t, err, rbac.ErrDuplicateRole)
	})

	t.Run("Create role with non-existing parent", func(t *testing.T) {
		nonExistingParentID := "660e8400-e29b-41d4-a716-446655440099"
		store.EXPECT().GetRole(ctx, nonExistingParentID).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
		_, err := r.CreateRole(ctx, "user", "description", nonExistingParentID)
		assert.Error(t, err)
	})

	t.Run("Create role successfully without parent", func(t *testing.T) {
		role, err := r.CreateRole(ctx, "user", "User role")
		assert.NoError(t, err)
		assert.Equal(t, "user", role.Name)
		assert.Equal(t, "User role", role.Description)
	})

	t.Run("Create role successfully with parent", func(t *testing.T) {
		role, err := r.CreateRole(ctx, "editor", "Editor role", adminID)
		assert.NoError(t, err)
		assert.Equal(t, "editor", role.Name)
		assert.Equal(t, "Editor role", role.Description)
		assert.Equal(t, adminID, role.ParentID)
	})
}

func TestUpdateRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)
	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	adminID := "550e8400-e29b-41d4-a716-446655440000"
	editorID := "550e8400-e29b-41d4-a716-446655440001"
	viewerID := "550e8400-e29b-41d4-a716-446655440002"

	existingAdmin := rbac.Role{ID: adminID, Name: "admin"}
	existingEditor := rbac.Role{ID: editorID, Name: "editor", ParentID: adminID}
	existingViewer := rbac.Role{ID: viewerID, Name: "viewer", ParentID: editorID}

	store.EXPECT().GetRole(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, id string) (rbac.Role, error) {
		switch id {
		case adminID:
			return existingAdmin, nil
		case editorID:
			return existingEditor, nil
		case viewerID:
			return existingViewer, nil
		default:
			return rbac.Role{}, rbac.ErrNotFound
		}
	}).AnyTimes()
	store.EXPECT().UpdateRole(ctx, gomock.Any()).Return(nil).Times(1)

	t.Run("Update role with invalid UUID", func(t *testing.T) {
		err := r.UpdateRole(ctx, "invalid-uuid", adminID)
		assert.NotNil(t, err)
	})

	t.Run("Update non-existing role", func(t *testing.T) {
		err := r.UpdateRole(ctx, "550e8400-e29b-41d4-a716-446655440099", adminID)
		assert.ErrorIs(t, err, rbac.ErrNotFound)
	})

	t.Run("Update role with invalid parent UUID", func(t *testing.T) {
		err := r.UpdateRole(ctx, viewerID, "invalid-parent-uuid")
		assert.NotNil(t, err)
	})

	t.Run("Update role with non-existing parent", func(t *testing.T) {
		err := r.UpdateRole(ctx, viewerID, "550e8400-e29b-41d4-a716-446655440099")
		assert.ErrorIs(t, err, rbac.ErrNotFound)
	})

	t.Run("Update role creates cycle", func(t *testing.T) {
		err := r.UpdateRole(ctx, adminID, editorID)
		assert.ErrorIs(t, err, rbac.ErrRoleCycle)
	})

	t.Run("Update role successfully", func(t *testing.T) {
		err := r.UpdateRole(ctx, viewerID, adminID)
		assert.NoError(t, err)
	})
}

func TestRemoveRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)
	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	roleID := "550e8400-e29b-41d4-a716-446655440000"

	store.EXPECT().GetRole(ctx, roleID).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetRole(ctx, roleID).Return(rbac.Role{ID: roleID, Name: "user"}, nil).Times(3)
	store.EXPECT().ListSubjects(ctx).Return([]string{"user1", "user2"}, nil).Times(3)
	store.EXPECT().GetSubject(ctx, "user1").Return(rbac.Subject{ID: "user1", RoleID: "some-other-role"}, nil).Times(3)
	store.EXPECT().GetSubject(ctx, "user2").Return(rbac.Subject{ID: "user2", RoleID: roleID}, nil).Times(1)
	store.EXPECT().GetSubject(ctx, "user2").Return(rbac.Subject{ID: "user2", RoleID: "another-role"}, nil).Times(2)
	store.EXPECT().RemoveRole(ctx, roleID).Return(rbac.ErrRoleHasChildren).Times(1)
	store.EXPECT().RemoveRole(ctx, roleID).Return(nil).Times(1)

	t.Run("Remove role with invalid UUID", func(t *testing.T) {
		err := r.RemoveRole(ctx, "invalid-uuid")
		assert.NotNil(t, err)
	})

	t.Run("Remove non-existing role", func(t *testing.T) {
		err := r.RemoveRole(ctx, roleID)
		assert.ErrorIs(t, err, rbac.ErrNotFound)
	})

	t.Run("Remove role that is in use", func(t *testing.T) {
		err := r.RemoveRole(ctx, roleID)
		assert.ErrorIs(t, err, rbac.ErrRoleInUse)
	})

	t.Run("Remove role that has children", func(t *testing.T) {
		err := r.RemoveRole(ctx, roleID)
		assert.ErrorIs(t, err, rbac.ErrRoleHasChildren)
	})

	t.Run("Remove role successfully", func(t *testing.T) {
		err := r.RemoveRole(ctx, roleID)
		assert.NoError(t, err)
	})
}
