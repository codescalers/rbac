package rbac

type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	BizRule  string `json:"biz_rule,omitempty"`
}

type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

type User struct {
	ID    string `json:"id"`
	Roles []Role `json:"roles"`
}
