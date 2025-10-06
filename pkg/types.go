package rbac

type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

type Grant struct {
	ID         string `json:"id"`
	Resource   string `json:"resource"`
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
}

type User struct {
	ID     string  `json:"id"`
	Roles  []Role  `json:"roles"`
	Grants []Grant `json:"grants"`
}
