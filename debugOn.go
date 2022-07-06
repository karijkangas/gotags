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

func (a *GoTags) initializeExtra(router *gin.Engine) {
	log.Println("WARNING: GOTAGS DEBUG API ENABLED.")
	router.POST(paths["debug+reset"], a.debugReset)
	router.GET(paths["debug+pending"], a.debugGetPending)
}

func (a *GoTags) debugReset(c *gin.Context) {
	tx, err := a.pool.Begin(context.Background())
	defer tx.Rollback(context.Background())

	b := &pgx.Batch{}
	b.Queue("DELETE FROM pending;")
	b.Queue("DELETE FROM users;")
	b.Queue("ALTER SEQUENCE users_id_seq RESTART;")
	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	_, err1 := r.Exec()
	_, err2 := r.Exec()
	_, err3 := r.Exec()

	if err1 != nil || err2 != nil || err3 != nil {
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

func (a *GoTags) debugGetPending(c *gin.Context) {
	category := c.Query("category")

	type outItem struct {
		ID    string         `json:"id"`
		Email string         `json:"email"`
		Data  map[string]any `json:"data"`
	}
	output := []outItem{}

	rows, err := a.pool.Query(context.Background(),
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
