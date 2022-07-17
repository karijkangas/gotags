//go:build gotags_debug_api

package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4"
)

/*
	Debug API provides support for automatic testing.
	NOT FOR PRODUCTION USE.

	go build --tags=gotags_debug_api
*/

func init() {
	addExtraInitialization(debugAPIExtra)
}

func debugAPIExtra(a *GoTags) {
	router := a.router
	log.Println("WARNING: GOTAGS DEBUG API ENABLED.")
	router.POST(paths["debug_reset"], a.debugAPIReset)
	router.GET(paths["debug_pending"], a.debugAPIGetPending)
}

func (a *GoTags) debugAPIReset(c *gin.Context) {
	tx, err := a.pool.Begin(context.Background())
	defer tx.Rollback(context.Background())

	b := &pgx.Batch{}
	b.Queue("DELETE FROM pending;")
	b.Queue("DELETE FROM limiter;")
	b.Queue("ALTER SEQUENCE limiter_id_seq RESTART;")
	b.Queue("DELETE FROM users;")
	b.Queue("ALTER SEQUENCE users_id_seq RESTART;")
	// TODO: tags
	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	_, err1 := r.Exec()
	_, err2 := r.Exec()
	_, err3 := r.Exec()
	_, err4 := r.Exec()
	_, err5 := r.Exec()

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	r.Close()

	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusOK)
}

func (a *GoTags) debugAPIGetPending(c *gin.Context) {
	category := c.Query("category")

	type outItem struct {
		ID    string         `json:"id"`
		Email string         `json:"email"`
		Data  map[string]any `json:"data"`
	}
	output := []outItem{}

	rows, err := a.pool.Query(
		context.Background(),
		`SELECT id, email, data FROM pending
		 WHERE category = $1
		 ORDER BY created_at ASC;`, category)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var item outItem
		err := rows.Scan(&item.ID, &item.Email, &item.Data)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		output = append(output, item)
	}

	if err := rows.Err(); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"category": category, "pending": output})
}
