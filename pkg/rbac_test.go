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

	tests := []struct {
		name          string
		roleName      string
		description   string
		parentID      string
		setupMock     func()
		expectedError error
		validateRole  func(role rbac.Role)
	}{
		{
			name:          "Create role with empty name",
			roleName:      "",
			description:   "description",
			expectedError: rbac.ErrInvalidName,
		},
		{
			name:          "Create role with duplicate name",
			roleName:      "admin",
			description:   "description",
			expectedError: rbac.ErrDuplicateRole,
		},
		{
			name:        "Create role with non-existing parent",
			roleName:    "user",
			description: "description",
			parentID:    "660e8400-e29b-41d4-a716-446655440099",
			setupMock: func() {
				store.EXPECT().GetRole(ctx, "660e8400-e29b-41d4-a716-446655440099").Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
			},
			expectedError: rbac.ErrNotFound,
		},
		{
			name:        "Create role successfully without parent",
			roleName:    "user",
			description: "User role",
			validateRole: func(role rbac.Role) {
				assert.Equal(t, "user", role.Name)
				assert.Equal(t, "User role", role.Description)
			},
		},
		{
			name:        "Create role successfully with parent",
			roleName:    "editor",
			description: "Editor role",
			parentID:    adminID,
			validateRole: func(role rbac.Role) {
				assert.Equal(t, "editor", role.Name)
				assert.Equal(t, "Editor role", role.Description)
				assert.Equal(t, adminID, role.ParentID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMock != nil {
				tt.setupMock()
			}

			var role rbac.Role
			var err error
			if tt.parentID != "" {
				role, err = r.CreateRole(ctx, tt.roleName, tt.description, tt.parentID)
			} else {
				role, err = r.CreateRole(ctx, tt.roleName, tt.description)
			}

			if tt.expectedError == nil {
				assert.NoError(t, err)
				if tt.validateRole != nil {
					tt.validateRole(role)
				}
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestUpdateRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	adminID := "550e8400-e29b-41d4-a716-446655440000"
	editorID := "550e8400-e29b-41d4-a716-446655440001"
	viewerID := "550e8400-e29b-41d4-a716-446655440002"

	existingAdmin := rbac.Role{ID: adminID, Name: "admin"}
	existingEditor := rbac.Role{ID: editorID, Name: "editor", ParentID: adminID}
	existingViewer := rbac.Role{ID: viewerID, Name: "viewer", ParentID: editorID}

	store.EXPECT().GetRoleByName(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, name string) (rbac.Role, error) {
		switch name {
		case "admin":
			return existingAdmin, nil
		case "editor":
			return existingEditor, nil
		case "viewer":
			return existingViewer, nil
		default:
			return rbac.Role{}, rbac.ErrNotFound
		}
	}).AnyTimes()
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

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		roleName       string
		newParentName  string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:          "Update non-existing role",
			roleName:      "nonexistent",
			newParentName: "admin",
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Update role with non-existing parent",
			roleName:      "viewer",
			newParentName: "nonexistent",
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Update role creates cycle",
			roleName:      "admin",
			newParentName: "editor",
			expectedError: rbac.ErrRoleCycle,
		},
		{
			name:          "Update role successfully",
			roleName:      "viewer",
			newParentName: "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.UpdateRole(ctx, tt.roleName, tt.newParentName)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestRemoveRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	roleName := "user"
	roleID := "550e8400-e29b-41d4-a716-446655440000"

	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{ID: roleID, Name: roleName}, nil).Times(3)
	store.EXPECT().ListSubjects(ctx).Return([]string{"user1", "user2"}, nil).Times(3)
	store.EXPECT().GetSubject(ctx, "user1").Return(rbac.Subject{ID: "user1", RoleID: "some-other-role"}, nil).Times(3)
	store.EXPECT().GetSubject(ctx, "user2").Return(rbac.Subject{ID: "user2", RoleID: roleID}, nil).Times(1)
	store.EXPECT().GetSubject(ctx, "user2").Return(rbac.Subject{ID: "user2", RoleID: "another-role"}, nil).Times(2)
	store.EXPECT().RemoveRole(ctx, roleID).Return(rbac.ErrRoleHasChildren).Times(1)
	store.EXPECT().RemoveRole(ctx, roleID).Return(nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		roleName       string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:          "Remove non-existing role",
			roleName:      roleName,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Remove role that is in use",
			roleName:      roleName,
			expectedError: rbac.ErrRoleInUse,
		},
		{
			name:          "Remove role that has children",
			roleName:      roleName,
			expectedError: rbac.ErrRoleHasChildren,
		},
		{
			name:     "Remove role successfully",
			roleName: roleName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.RemoveRole(ctx, tt.roleName)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestCreatePermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	store.EXPECT().ListPermissions(ctx).Return([]rbac.Permission{
		{ID: "p1", Resource: "blog", Action: "read", BizRule: ""},
	}, nil).AnyTimes()
	store.EXPECT().CreatePermission(ctx, gomock.Any()).Return(nil).Times(2)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name          string
		resource      string
		action        string
		bizRuleName   []string
		expectedError error
		validatePerm  func(*rbac.Permission)
	}{
		{
			name:          "Create permission with empty resource",
			resource:      "",
			action:        "read",
			expectedError: rbac.ErrInvalidResourceOrAction,
		},
		{
			name:          "Create permission with empty action",
			resource:      "blog",
			action:        "",
			expectedError: rbac.ErrInvalidResourceOrAction,
		},
		{
			name:          "Create duplicate permission",
			resource:      "blog",
			action:        "read",
			expectedError: rbac.ErrDuplicatePermission,
		},
		{
			name:     "Create permission successfully without bizrule",
			resource: "article",
			action:   "write",
			validatePerm: func(p *rbac.Permission) {
				assert.NotEmpty(t, p.ID)
				assert.Equal(t, "article", p.Resource)
				assert.Equal(t, "write", p.Action)
				assert.Equal(t, "", p.BizRule)
			},
		},
		{
			name:        "Create permission successfully with bizrule",
			resource:    "post",
			action:      "delete",
			bizRuleName: []string{"is_owner"},
			validatePerm: func(p *rbac.Permission) {
				assert.NotEmpty(t, p.ID)
				assert.Equal(t, "post", p.Resource)
				assert.Equal(t, "delete", p.Action)
				assert.Equal(t, "is_owner", p.BizRule)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, err := r.CreatePermission(ctx, tt.resource, tt.action, tt.bizRuleName...)

			if tt.expectedError == nil {
				assert.NoError(t, err)
				if tt.validatePerm != nil {
					tt.validatePerm(&perm)
				}
				return
			}

			assert.Error(t, err)
			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}

func TestRemovePermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	permID := "550e8400-e29b-41d4-a716-446655440000"
	roleID := "550e8400-e29b-41d4-a716-446655440001"

	store.EXPECT().GetPermission(ctx, permID).Return(rbac.Permission{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetPermission(ctx, permID).Return(rbac.Permission{ID: permID}, nil).Times(2)
	store.EXPECT().ListRoles(ctx).Return([]rbac.Role{
		{
			ID:   roleID,
			Name: "admin",
			Permissions: []rbac.Permission{
				{ID: permID, Resource: "blog", Action: "read"},
			},
		},
	}, nil).Times(1)
	store.EXPECT().ListRoles(ctx).Return([]rbac.Role{
		{
			ID:          roleID,
			Name:        "admin",
			Permissions: []rbac.Permission{},
		},
	}, nil).Times(1)
	store.EXPECT().RemovePermission(ctx, permID).Return(nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		permID         string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:           "Remove permission with invalid UUID",
			permID:         "invalid-uuid",
			expectAnyError: true,
		},
		{
			name:          "Remove non-existing permission",
			permID:        permID,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Remove permission that is in use",
			permID:        permID,
			expectedError: rbac.ErrPermissionInUse,
		},
		{
			name:   "Remove permission successfully",
			permID: permID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.RemovePermission(ctx, tt.permID)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestAddPermissionToRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	roleName := "editor"
	permID := "550e8400-e29b-41d4-a716-446655440001"
	existingPermID := "550e8400-e29b-41d4-a716-446655440002"

	existingPerm := rbac.Permission{ID: existingPermID, Resource: "blog", Action: "read"}
	newPerm := rbac.Permission{ID: permID, Resource: "article", Action: "write"}

	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{
		ID:          "550e8400-e29b-41d4-a716-446655440000",
		Name:        roleName,
		Permissions: []rbac.Permission{existingPerm},
	}, nil).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{
		ID:          "550e8400-e29b-41d4-a716-446655440000",
		Name:        roleName,
		Permissions: []rbac.Permission{},
	}, nil).Times(2)
	store.EXPECT().GetPermission(ctx, permID).Return(rbac.Permission{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetPermission(ctx, permID).Return(newPerm, nil).Times(1)
	store.EXPECT().UpdateRole(ctx, gomock.Any()).Return(nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		roleName       string
		permID         string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:           "Add permission with invalid permission UUID",
			roleName:       roleName,
			permID:         "invalid-uuid",
			expectAnyError: true,
		},
		{
			name:          "Add permission to non-existing role",
			roleName:      roleName,
			permID:        permID,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Add duplicate permission to role",
			roleName:      roleName,
			permID:        existingPermID,
			expectedError: rbac.ErrAlreadyExists,
		},
		{
			name:          "Add non-existing permission to role",
			roleName:      roleName,
			permID:        permID,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:     "Add permission to role successfully",
			roleName: roleName,
			permID:   permID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.AddPermissionToRole(ctx, tt.roleName, tt.permID)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestRemovePermissionFromRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	roleName := "editor"
	roleID := "550e8400-e29b-41d4-a716-446655440000"
	permID := "550e8400-e29b-41d4-a716-446655440001"
	otherPermID := "550e8400-e29b-41d4-a716-446655440002"

	existingPerm := rbac.Permission{ID: permID, Resource: "blog", Action: "read"}

	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{
		ID:          roleID,
		Name:        roleName,
		Permissions: []rbac.Permission{},
	}, nil).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{
		ID:          roleID,
		Name:        roleName,
		Permissions: []rbac.Permission{existingPerm},
	}, nil).Times(1)
	store.EXPECT().UpdateRole(ctx, gomock.Any()).Return(nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		roleName       string
		permID         string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:           "Remove permission with invalid permission UUID",
			roleName:       roleName,
			permID:         "invalid-uuid",
			expectAnyError: true,
		},
		{
			name:          "Remove permission from non-existing role",
			roleName:      roleName,
			permID:        permID,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:          "Remove non-existing permission from role",
			roleName:      roleName,
			permID:        otherPermID,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:     "Remove permission from role successfully",
			roleName: roleName,
			permID:   permID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.RemovePermissionFromRole(ctx, tt.roleName, tt.permID)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

func TestAssignRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	roleName := "admin"
	roleID := "550e8400-e29b-41d4-a716-446655440000"
	subjectID := "subject-123"

	existingSubject := rbac.Subject{ID: subjectID, RoleID: ""}

	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetRoleByName(ctx, roleName).Return(rbac.Role{ID: roleID, Name: roleName}, nil).Times(2)
	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{}, rbac.ErrNotFound).Times(1)
	store.EXPECT().GetSubject(ctx, subjectID).Return(existingSubject, nil).Times(1)
	store.EXPECT().UpdateSubject(ctx, rbac.Subject{ID: subjectID, RoleID: roleID}).Return(nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	tests := []struct {
		name           string
		subjectID      string
		roleName       string
		expectedError  error
		expectAnyError bool
	}{
		{
			name:          "Assign non-existing role",
			subjectID:     subjectID,
			roleName:      roleName,
			expectedError: rbac.ErrNotFound,
		},
		{
			name:           "Assign role to non-existing subject",
			subjectID:      subjectID,
			roleName:       roleName,
			expectAnyError: true,
		},
		{
			name:      "Assign role successfully",
			subjectID: subjectID,
			roleName:  roleName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.AssignRole(ctx, tt.subjectID, tt.roleName)

			if tt.expectedError == nil && !tt.expectAnyError {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}

type MockResource struct {
	name    string
	ownerID string
}

func (mr MockResource) Name() string {
	return mr.name
}

type MockOwnershipBizRule struct{}

func (mbr MockOwnershipBizRule) Name() string {
	return "test_ownership"
}

func (mbr MockOwnershipBizRule) Evaluate(ctx context.Context, subjectID string, resource rbac.Resource) (bool, error) {
	mockRes, ok := resource.(MockResource)
	if !ok {
		return false, nil
	}
	return mockRes.ownerID == subjectID, nil
}

func TestCan(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	store := mocks.NewMockStore(ctrl)

	subjectID := "subject-123"
	otherSubjectID := "subject-456"
	adminRoleID := "550e8400-e29b-41d4-a716-446655440000"
	userRoleID := "550e8400-e29b-41d4-a716-446655440001"
	readPermID := "perm-read-123"
	writePermID := "perm-write-123"
	deleteWithRulePermID := "perm-delete-123"

	adminRole := rbac.Role{
		ID:   adminRoleID,
		Name: "admin",
		Permissions: []rbac.Permission{
			{ID: readPermID, Resource: "blog", Action: "read"},
			{ID: writePermID, Resource: "blog", Action: "write"},
		},
	}

	userRole := rbac.Role{
		ID:       userRoleID,
		Name:     "user",
		ParentID: adminRoleID,
		Permissions: []rbac.Permission{
			{ID: deleteWithRulePermID, Resource: "blog", Action: "delete", BizRule: "test_ownership"},
		},
	}

	resource := MockResource{name: "blog", ownerID: subjectID}

	store.EXPECT().GetRole(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, id string) (rbac.Role, error) {
		switch id {
		case adminRoleID:
			return adminRole, nil
		case userRoleID:
			return userRole, nil
		default:
			return rbac.Role{}, rbac.ErrNotFound
		}
	}).AnyTimes()

	store.EXPECT().GetSubject(ctx, "non-existing").Return(rbac.Subject{}, rbac.ErrNotFound).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: ""}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: "invalid-uuid"}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: adminRoleID}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: adminRoleID}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: userRoleID}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, subjectID).Return(rbac.Subject{ID: subjectID, RoleID: userRoleID}, nil).Times(1)

	store.EXPECT().GetSubject(ctx, otherSubjectID).Return(rbac.Subject{ID: otherSubjectID, RoleID: userRoleID}, nil).Times(1)

	r, err := rbac.NewRBAC(ctx, store)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	err = r.RegisterBizRule(MockOwnershipBizRule{})
	assert.NoError(t, err)

	tests := []struct {
		name           string
		subjectID      string
		action         string
		resource       rbac.Resource
		expectedResult bool
		expectError    bool
	}{
		{
			name:        "Subject not found",
			subjectID:   "non-existing",
			action:      "read",
			resource:    resource,
			expectError: true,
		},
		{
			name:           "Subject without role",
			subjectID:      subjectID,
			action:         "read",
			resource:       resource,
			expectedResult: false,
			expectError:    false,
		},
		{
			name:        "Subject with invalid role UUID",
			subjectID:   subjectID,
			action:      "read",
			resource:    resource,
			expectError: true,
		},
		{
			name:           "Subject does not have permission",
			subjectID:      subjectID,
			action:         "update",
			resource:       resource,
			expectedResult: false,
			expectError:    false,
		},
		{
			name:           "Subject has direct permission",
			subjectID:      subjectID,
			action:         "read",
			resource:       resource,
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "Subject has permission via hierarchy",
			subjectID:      subjectID,
			action:         "write",
			resource:       resource,
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "Subject has permission with business rule (passes)",
			subjectID:      subjectID,
			action:         "delete",
			resource:       resource,
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "Subject has permission with business rule (fails)",
			subjectID:      otherSubjectID,
			action:         "delete",
			resource:       resource,
			expectedResult: false,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := r.Can(ctx, tt.subjectID, tt.action, tt.resource)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
