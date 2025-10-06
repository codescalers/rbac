package rbac

var (
	ErrNotFound      = errorString("not found")
	ErrAlreadyExists = errorString("already exists")
)

type errorString string

func (e errorString) Error() string { return string(e) }
