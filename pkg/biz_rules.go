package rbac

import (
	"context"
	"fmt"
)

// Resource represents any entity that can be accessed or modified
type Resource interface {
	Name() string
}

// BizRule defines a custom business rule for fine-grained authorization
type BizRule interface {
	Name() string
	Evaluate(ctx context.Context, subjectID string, resource Resource) (bool, error)
}

// RegisterBizRule registers a custom business rule
func (r *RBAC) RegisterBizRule(rule BizRule) error {
	if rule == nil {
		return fmt.Errorf("business rule cannot be nil")
	}

	name := rule.Name()
	if name == "" {
		return fmt.Errorf("business rule name cannot be empty")
	}

	if r.bizRules == nil {
		r.bizRules = make(map[string]BizRule)
	}

	if _, exists := r.bizRules[name]; exists {
		return fmt.Errorf("business rule %q already registered", name)
	}

	r.bizRules[name] = rule
	return nil
}

// GetBizRule retrieves a registered business rule by name
func (r *RBAC) GetBizRule(name string) (BizRule, bool) {
	if r.bizRules == nil {
		return nil, false
	}

	rule, exists := r.bizRules[name]
	return rule, exists
}
