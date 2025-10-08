package middleware

import (
	"net/http"

	rbac "github.com/codescalers/rbac/pkg"
)

// errorResponse represents an HTTP error response
type errorResponse struct {
	StatusCode int
	Error      string
	Message    string
}

// handleError converts RBAC errors to appropriate HTTP error responses
func handleError(err error) errorResponse {
	switch err {
	case rbac.ErrNotFound:
		return errorResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Unauthorized",
			Message:    "User not found or not assigned to any role",
		}
	case rbac.ErrInvalidName, rbac.ErrInvalidResourceOrAction:
		return errorResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Bad Request",
			Message:    err.Error(),
		}
	default:
		return errorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal Server Error",
			Message:    err.Error(),
		}
	}
}
