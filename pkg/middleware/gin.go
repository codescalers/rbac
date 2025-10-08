package middleware

import (
	"net/http"

	rbac "github.com/codescalers/rbac/pkg"
	"github.com/gin-gonic/gin"
)

// GinConfig holds configuration for Gin middleware
type GinConfig struct {
	RBAC              *rbac.RBAC
	Action            string
	SubjectExtractor  GinSubjectExtractor
	ResourceExtractor GinResourceExtractor
}

type GinSubjectExtractor func(*gin.Context) string

type GinResourceExtractor func(*gin.Context) rbac.Resource

func RequirePermissionGin(config GinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract subject ID
		subjectID := ""
		if config.SubjectExtractor != nil {
			subjectID = config.SubjectExtractor(c)
		}

		if subjectID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: Subject ID not found"})
			c.Abort()
			return
		}

		// Extract resource
		var resource rbac.Resource
		if config.ResourceExtractor != nil {
			resource = config.ResourceExtractor(c)
		}

		// Check permission
		allowed, err := config.RBAC.Can(c.Request.Context(), subjectID, config.Action, resource)
		if err != nil {
			errResp := handleError(err)
			c.JSON(errResp.StatusCode, gin.H{
				"error":   errResp.Error,
				"message": errResp.Message,
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied for this resource"})
			c.Abort()
			return
		}

		c.Next()
	}
}
