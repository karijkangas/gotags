//go:build !gotags_debug_api

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// ******************************************************************
func TestDebugGetPendingJoin(t *testing.T) {
	category := "join"
	p := fmt.Sprintf("%s?category=%s", paths["debug+pending"], category)
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusNotFound)
}
