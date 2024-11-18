// internal/handler/handler.go

package handler

import (
	"otp-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

// BaseHandler contains common handler functionality
type BaseHandler struct{}

// handleError standardizes error responses
func (h *BaseHandler) handleError(c *gin.Context, err error) {
	utils.RespondWithError(c, err)
}
