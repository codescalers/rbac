package rbac

// Permission represents an action that can be performed on a resource
type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	BizRule  string `json:"biz_rule,omitempty"`
}

// Role represents a collection of permissions with optional parent hierarchy
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	ParentID    string       `json:"parent_id,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// Subject represents a subject with a single assigned role
type Subject struct {
	ID     string `json:"id"`
	RoleID string `json:"role_id"`
}
