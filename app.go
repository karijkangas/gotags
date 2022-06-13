package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
)

type checkSignupData struct {
	Email string `json:"email" binding:"required,email"`
}

type signupData struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=1"`
}

type signinData struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type deleteAccountData struct {
	Password string `json:"password" binding:"required"`
}

type mailer func(email, url string) error

func sasMailer(email, url string) error {
	fmt.Printf("********** sas mailer: %s %s\n", email, url)
	return nil
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
		var id int
		err := a.pool.QueryRow(
			context.Background(),
			`SELECT user_id FROM sessions WHERE id = $1;`,
			token[0]).Scan(&id)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", id)
		c.Next()
	}
}

func (a *GoTags) initialize(databaseURL string) {
	pool, err := pgxpool.Connect(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	router := gin.Default()

	router.POST("/api/signups/check", a.checkSignup)
	router.POST("/api/signups", a.signup)
	router.POST("/api/signups/verify", a.verifySignup)
	router.POST("/api/signin", a.signin)

	authorized := router.Group("/api/auth")
	authorized.Use(a.auth())
	{
		authorized.DELETE("/account", a.deleteAccount)
		authorized.GET("/tags/:id", a.tag)
	}

	a.pool = pool
	a.router = router
	a.mailer = sasMailer
}

func (a *GoTags) run(server string) {
	a.router.Run(server)
}

func (a *GoTags) checkSignup(c *gin.Context) {
	var d checkSignupData
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// check if email already used by registered user
	var exists bool
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		d.Email)
	err := row.Scan(&exists)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	if exists {
		c.Status(http.StatusConflict)
		return
	}

	c.Status(http.StatusOK)
}

func (a *GoTags) signup(c *gin.Context) {
	var d signupData
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(d.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// check if email already registered
	var exists bool
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		d.Email)
	err = row.Scan(&exists)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if exists {
		c.Status(http.StatusConflict)
		return
	}

	// add signup data to verifications
	data := map[string]string{
		"name":          d.Name,
		"password_hash": string(passwordHash),
	}
	var uuid string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO verifications (email, category, data)
			VALUES ($1, 'signup', $2)
			RETURNING id;`,
		d.Email, data)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// create verify signup url
	req, err := http.NewRequest("GET", "/signup/verify", nil)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	q := url.Values{}
	q.Add("id", uuid)
	req.URL.RawQuery = q.Encode()

	// send message with a link to verify signup
	// in case of error, a periodic task will remove stale signup data
	// TODO: use async queue with retry?
	err = a.mailer(d.Email, req.URL.String())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

func (a *GoTags) verifySignup(c *gin.Context) {
	id := c.Query("id")

	// find matching signup verification
	var email string
	data := map[string]string{}
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email, data FROM verifications WHERE category = 'signup' AND id = $1;`,
		id)
	err := row.Scan(&email, &data)

	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	// add user
	var userID int
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO users (name, email, password_hash)
			VALUES ($1, $2, $3)
			ON CONFLICT (email) DO UPDATE
			SET name=EXCLUDED.name, password_hash=EXCLUDED.password_hash
			RETURNING id;`,
		data["name"], email, data["password_hash"])
	err = row.Scan(&userID)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// remove signups matching the email and create a session
	var token string
	b := &pgx.Batch{}
	b.Queue(`DELETE FROM verifications WHERE email = $1 AND category = 'signup';`, email)
	b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, userID)
	r := a.pool.SendBatch(context.Background(), b)
	r.Exec()           // delete, ignore errors
	row = r.QueryRow() // insert
	err = row.Scan(&token)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (a *GoTags) signin(c *gin.Context) {
	var d signinData
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// find user id and password_hash
	var id int
	var passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT id, password_hash FROM users WHERE email = $1;`,
		d.Email)
	err := row.Scan(&id, &passwordHash)

	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(d.Password))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// create a session and return token
	var token string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id)
			VALUES ($1)
			RETURNING id;`,
		id)
	err = row.Scan(&token)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (a *GoTags) deleteAccount(c *gin.Context) {
	var d deleteAccountData
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	userID := c.GetInt("user")
	if userID == 0 {
		c.Status(http.StatusUnauthorized)
		return
	}

	var passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT password_hash FROM users WHERE id = $1;`,
		userID)
	err := row.Scan(&passwordHash)

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(d.Password))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	_, err = a.pool.Exec(
		context.Background(),
		`DELETE FROM users WHERE id = $1;`, userID)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusOK)
}

func (a *GoTags) tag(c *gin.Context) {
	id := c.Param("id")

	// TODO: tag data

	c.JSON(http.StatusOK, gin.H{"tag": id})
}
