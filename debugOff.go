//go:build !gotags_debug_api

package main

import (
	"github.com/gin-gonic/gin"
)

func (a *GoTags) initializeExtra(router *gin.Engine) {}
