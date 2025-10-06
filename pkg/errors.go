package rbac

var (
	ErrAlreadyExists           = errorString("already exists")
	ErrInvalidResourceOrAction = errorString("invalid resource or action")
	ErrInvalidName             = errorString("invalid name")
)

type errorString string

func (e errorString) Error() string { return string(e) }
