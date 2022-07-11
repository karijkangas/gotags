package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
)

const (
	passwordHashCost = bcrypt.DefaultCost
	cleanupDBTimeUTC = "04:00"
	verificationsTTL = "'1 day'"
)

type mailer func(email, url, lang string) error

func sasMailer(email, url, lang string) error {
	fmt.Printf("********** sas mailer: %s %s %s\n", email, url, lang)
	return nil
}

func defaultProfile() map[string]any {
	return map[string]any{}
}

var paths = map[string]string{
	"signin":        "/api/signin",
	"join":          "/api/join",
	"joinCheck":     "/api/join/check",
	"joinActivate":  "/api/join/activate",
	"resetPassword": "/api/reset-password",
	"newPassword":   "/api/reset-password/new",
	"auth":          "",
	"auth+account":  "/api/auth/account",
	"auth+profile":  "/api/auth/profile",
	"auth+password": "/api/auth/password",
	"auth+tags":     "/api/auth/tags/:id",
	//
	"debug+reset":   "/debug/reset",
	"debug+pending": "/debug/pending",
}

// GoTags ...
type GoTags struct {
	pool   *pgxpool.Pool
	router *gin.Engine
	mailer mailer
}

func (a *GoTags) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := c.Request.Header["Token"]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var user int
		err := a.pool.QueryRow(
			context.Background(),
			`SELECT user_id FROM sessions WHERE id = $1;`,
			token[0]).Scan(&user)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func (a *GoTags) initialize(databaseURL string) {
	pool, err := pgxpool.Connect(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	router := gin.Default()

	router.POST(paths["signin"], a.signin)
	router.POST(paths["join"], a.join)
	router.POST(paths["joinCheck"], a.joinCheck)
	router.POST(paths["joinActivate"], a.joinActivate)
	router.POST(paths["resetPassword"], a.resetPassword)
	router.POST(paths["newPassword"], a.newPassword)

	authorized := router.Group(paths["auth"])
	authorized.Use(a.auth())
	{
		authorized.GET(paths["auth+account"], a.getAccount)
		authorized.PUT(paths["auth+account"], a.updateAccount)
		authorized.DELETE(paths["auth+account"], a.deleteAccount)
		authorized.GET(paths["auth+profile"], a.getProfile)
		authorized.PUT(paths["auth+profile"], a.updateProfile)
		authorized.POST(paths["auth+password"], a.updatePassword)
		authorized.GET(paths["auth+tags"], a.tag)
	}

	// initialize gotags debug api with "go test --tags=gotags_debug_api"
	a.initializeExtra(router)

	a.pool = pool
	a.router = router
	a.mailer = sasMailer

	s := gocron.NewScheduler(time.UTC)
	s.Every(1).Day().At(cleanupDBTimeUTC).Do(a.cleanupDB)
	s.StartAsync()
}

func (a *GoTags) run(server string) {
	a.router.Run(server)
}

func (a *GoTags) cleanupDB() {
	log.Printf("Running database cleanup")
	a.pool.Exec(context.Background(),
		fmt.Sprintf(`DELETE FROM pending WHERE created_at < now() - interval %s;`, verificationsTTL))
}

//
func (a *GoTags) signin(c *gin.Context) {
	var d struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email
	password := d.Password

	// get use data and profile
	var user int
	var data map[string]any
	var name, passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`WITH xuser AS (
			SELECT id, name, password_hash FROM users WHERE email = $1
		 )
		 SELECT u.id, name, password_hash, data FROM profiles AS p JOIN xuser AS u ON p.id = u.id;`,
		email)
	err1 := row.Scan(&user, &name, &passwordHash, &data)

	// validate password
	err2 := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))

	// missing user or invalid email
	if err1 != nil || err2 != nil {
		c.Status(http.StatusUnauthorized)
		return
	}

	// create a session
	var token string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id)
			VALUES ($1)
			RETURNING id;`,
		user)
	err := row.Scan(&token)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "profile": data, "token": token})
}

//
func (a *GoTags) join(c *gin.Context) {
	var d struct {
		Name     string         `json:"name" binding:"required,min=1"`
		Email    string         `json:"email" binding:"required,email"`
		Password string         `json:"password" binding:"required,min=1"`
		Lang     string         `json:"lang"`
		Extra    map[string]any `json:"extra"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	name := d.Name
	email := d.Email
	password := d.Password
	extra := d.Extra
	lang := d.Lang

	// check if email available
	var exists bool
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		email)
	err := row.Scan(&exists)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if exists {
		c.Status(http.StatusConflict)
		return
	}

	// add join to pending
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	data := map[string]any{
		"name":          name,
		"password_hash": string(passwordHash),
		"extra":         extra,
	}
	var uuid string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, data)
			VALUES ($1, 'join', $2)
			RETURNING id;`,
		email, data)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// create join activate url
	req, err := http.NewRequest("GET", paths["joinActivate"], nil)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	q := url.Values{}
	q.Add("id", uuid)
	req.URL.RawQuery = q.Encode()

	// send message with a link
	err = a.mailer(email, req.URL.String(), lang)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) joinCheck(c *gin.Context) {
	var d struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email

	// check email available
	var exists bool
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		email)
	err := row.Scan(&exists)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if exists {
		c.Status(http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": email})
}

//
func (a *GoTags) joinActivate(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// get matching pending join
	var email string
	data := map[string]any{}
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email, data FROM pending WHERE category = 'join' AND id = $1;`,
		id)
	err := row.Scan(&email, &data)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	// validate email and password
	name := (data["name"]).(string)
	passwordHash := (data["password_hash"]).(string)
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if email != d.Email || err != nil {
		c.Status(http.StatusUnauthorized)
		return
	}
	extra := data["extra"]

	// do transaction: add user, remove pending, add session and profile
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background()) // safe to call after commit

	// add user
	var user int
	row = tx.QueryRow(
		context.Background(),
		`INSERT INTO users (name, email, password_hash)
			VALUES ($1, $2, $3)
			ON CONFLICT (email) DO UPDATE
			SET name=EXCLUDED.name, password_hash=EXCLUDED.password_hash
			RETURNING id;`,
		name, email, passwordHash)
	err = row.Scan(&user)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	profile := defaultProfile()
	var newProfile map[string]any

	// batched: remove pending join, create a session and a profile
	// use existing profile, if any
	var token string
	b := &pgx.Batch{}
	b.Queue(`DELETE FROM pending WHERE email = $1 AND category = 'join';`, email)
	b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	b.Queue(`WITH ins AS(
				INSERT INTO profiles (id, data) 
			   	VALUES ($1, $2)
				ON CONFLICT(id) DO NOTHING
				RETURNING data
			)
			SELECT * FROM ins
			UNION
				SELECT data FROM profiles WHERE id=$1;`, user, profile)
	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	_, err1 := r.Exec()                    // delete pending
	err2 := r.QueryRow().Scan(&token)      // insert session
	err3 := r.QueryRow().Scan(&newProfile) // insert profile

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

	c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "profile": newProfile, "token": token, "extra": extra})
}

//
func (a *GoTags) resetPassword(c *gin.Context) {
	var d struct {
		Email string `json:"email" binding:"required,email"`
		Lang  string `json:"lang"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email
	lang := d.Lang

	// find user with matching email
	var user int
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT id FROM users WHERE email = $1;`,
		email)
	err := row.Scan(&user)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	// add pending reset password data
	var uuid string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category)
			VALUES ($1, 'reset_password')
			RETURNING id;`,
		email)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// create reset password url
	req, err := http.NewRequest("GET", paths["resetPasswordVerify"], nil)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	q := url.Values{}
	q.Add("id", uuid)
	req.URL.RawQuery = q.Encode()

	// send message with a link to complete password reset
	err = a.mailer(email, req.URL.String(), lang)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) newPassword(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// find matching pending password reset
	var email string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email FROM pending WHERE category = 'reset_password' AND id = $1;`,
		id)
	err := row.Scan(&email)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	if email != d.Email {
		c.Status(http.StatusUnauthorized)
		return
	}

	// generate password hash
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// do as transaction: delete pending, update user password, add session and get profile
	tx, err := a.pool.Begin(context.Background())
	defer tx.Rollback(context.Background()) // safe to call after commit

	// delete request and update user password
	b := &pgx.Batch{}
	b.Queue(`DELETE FROM pending WHERE category = 'reset_password' AND id = $1;`, id)
	b.Queue(`UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id, name;`, passwordHash, email)
	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	var user int
	var name string
	// var profile map[string]any

	r.Exec()                              // delete, ignore errors
	err = r.QueryRow().Scan(&user, &name) // update, check user gone

	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	r.Close()

	b = &pgx.Batch{}
	b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	b.Queue(`SELECT data FROM profiles WHERE id = $1;`, user)
	r = tx.SendBatch(context.Background(), b)
	defer r.Close()

	var token string
	var profile map[string]any

	err1 := r.QueryRow().Scan(&token)
	err2 := r.QueryRow().Scan(&profile)

	if err1 != nil || err2 != nil {
		c.Status(http.StatusGone)
		return
	}
	r.Close()

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "profile": profile, "token": token})
}

//
func (a *GoTags) getAccount(c *gin.Context) {
	id := c.GetInt("user")

	var name string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT name FROM users WHERE id = $1;`,
		id)
	err := row.Scan(&name)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"name": name})
}

//
func (a *GoTags) updateAccount(c *gin.Context) {
	var d struct {
		Name string `json:"name" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	name := d.Name
	id := c.GetInt("user")

	row := a.pool.QueryRow(
		context.Background(),
		`UPDATE users SET name = $1
			WHERE id = $2 
			RETURNING name;`,
		name, id)
	var newName string
	err := row.Scan(&newName)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"name": newName})
}

//
func (a *GoTags) deleteAccount(c *gin.Context) {
	var d struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	password := d.Password
	user := c.GetInt("user")

	var email string
	var passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email, password_hash FROM users WHERE id = $1;`,
		user)
	err := row.Scan(&email, &passwordHash)

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if email != d.Email || err != nil {
		c.Status(http.StatusConflict)
		return
	}

	_, err = a.pool.Exec(
		context.Background(),
		`DELETE FROM users WHERE id = $1;`, user)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusNoContent)
}

//
func (a *GoTags) getProfile(c *gin.Context) {
	id := c.GetInt("user")

	var data map[string]any
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT data FROM profiles WHERE id = $1;`,
		id)
	err := row.Scan(&data)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

//
func (a *GoTags) updateProfile(c *gin.Context) {
	var d struct {
		Data map[string]any `json:"data" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	data := d.Data
	id := c.GetInt("user")

	row := a.pool.QueryRow(
		context.Background(),
		`UPDATE profiles SET data = $1
			WHERE id = $2
			RETURNING data;`,
		data, id)

	var newData map[string]any
	err := row.Scan(&newData)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": newData})
}

//
func (a *GoTags) updatePassword(c *gin.Context) {
	var d struct {
		Password    string `json:"password" binding:"required,min=1"`
		NewPassword string `json:"newPassword" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	password := d.Password
	newPassword := d.NewPassword
	user := c.GetInt("user")

	// get current password hash
	var hash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT password_hash FROM users WHERE id = $1;`,
		user)
	err := row.Scan(&hash)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		c.Status(http.StatusConflict)
		return
	}

	// generate new password hash
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), passwordHashCost)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// update password hash
	_, err = a.pool.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2;`, newHash, user)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusOK)
}

//
func (a *GoTags) tag(c *gin.Context) {
	id := c.Param("id")

	// TODO: tag data

	c.JSON(http.StatusOK, gin.H{"tag": id})
}
