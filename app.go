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

const (
	passwordHashCost = bcrypt.DefaultCost
)

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

	router.POST("/api/signups/check", a.checkSignup)
	router.POST("/api/signups", a.signup)
	router.POST("/api/signups/verify", a.verifySignup)
	router.POST("/api/signin", a.signin)
	router.POST("/api/resetpw", a.resetPassword)
	router.POST("/api/resetpw/verify", a.verifyResetPassword)

	authorized := router.Group("/api/auth")
	authorized.Use(a.auth())
	{
		authorized.PATCH("/account", a.modifyAccount)
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

//
func (a *GoTags) checkSignup(c *gin.Context) {
	var d struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email

	// check if email already used by registered user
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

	c.Status(http.StatusOK)
}

//
func (a *GoTags) signup(c *gin.Context) {
	var d struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	name := d.Name
	email := d.Email
	password := d.Password

	// check if email already registered
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

	// add signup data to verifications
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	data := map[string]string{
		"name":          name,
		"password_hash": string(passwordHash),
	}
	var uuid string
	row = a.pool.QueryRow(
		context.Background(),
		`INSERT INTO verifications (email, category, data)
			VALUES ($1, 'signup', $2)
			ON CONFLICT ON CONSTRAINT unique_per_category
			DO UPDATE
			SET data=EXCLUDED.data
			RETURNING id;`,
		email, data)
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

	// send email with a link to verify signup
	err = a.mailer(email, req.URL.String())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) verifySignup(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

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

	// validate password
	name := data["name"]
	passwordHash := data["password_hash"]
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// add user
	var user int
	row = a.pool.QueryRow(
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

	// remove signup and create a session
	var token string
	b := &pgx.Batch{}
	b.Queue(`DELETE FROM verifications WHERE email = $1 AND category = 'signup';`, email)
	b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	r := a.pool.SendBatch(context.Background(), b)
	r.Exec()           // delete, ignore errors
	row = r.QueryRow() // insert
	err = row.Scan(&token)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "token": token})
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

	// find user id and password_hash
	var user int
	var name, passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT id, name, password_hash FROM users WHERE email = $1;`,
		email)
	err := row.Scan(&user, &name, &passwordHash)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
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
		user)
	err = row.Scan(&token)

	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "token": token})
}

//
func (a *GoTags) resetPassword(c *gin.Context) {
	var d struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email

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

	// add reset password to verifications
	var uuid string
	row = a.pool.QueryRow(
		context.Background(),
		// `INSERT INTO verifications (email, category)
		// 	VALUES ($1, 'reset_password')
		// 	ON CONFLICT ON CONSTRAINT unique_per_category
		// 	DO NOTHING
		// 	RETURNING id;`,
		`WITH insert_reset_password AS (
			INSERT INTO verifications (email, category)
			VALUES ($1, 'reset_password')
			ON CONFLICT ON CONSTRAINT unique_per_category
			DO NOTHING
			RETURNING id
		 ) SELECT COALESCE(
			(SELECT id FROM insert_reset_password),
			(SELECT id FROM verifications WHERE email = $1 AND category = 'reset_password')
		 );`,
		email)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// create reset password url
	req, err := http.NewRequest("GET", "/resetpw/verify", nil)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	q := url.Values{}
	q.Add("id", uuid)
	req.URL.RawQuery = q.Encode()

	// send message with a link to complete password reset
	err = a.mailer(email, req.URL.String())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) verifyResetPassword(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// find matching signup verification
	var email string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email FROM verifications WHERE category = 'reset_password' AND id = $1;`,
		id)
	err := row.Scan(&email)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	//
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	//
	b := &pgx.Batch{}
	b.Queue(`UPDATE users SET password_hash = $1 WHERE email = $2;`, passwordHash, email)
	b.Queue(`DELETE FROM verifications WHERE email = $1 AND category = 'password_reset';`, email)
	r := a.pool.SendBatch(context.Background(), b)
	_, err = r.Exec()
	r.Exec() // delete, ignore errors

	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusOK)
}

//
func (a *GoTags) modifyAccount(c *gin.Context) {
	var d struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	name := d.Name
	password := d.Password

	var passwordHash string

	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		passwordHash = string(hash)
	}
	user := c.GetInt("user")

	// TODO: better solution?
	i := 0
	b := &pgx.Batch{}
	if name != "" {
		b.Queue(`UPDATE users SET name = $1 WHERE id = $2;`, name, user)
		i++
	}
	if passwordHash != "" {
		b.Queue(`UPDATE users SET password_hash = $1 WHERE id = $2;`, passwordHash, user)
		i++
	}
	r := a.pool.SendBatch(context.Background(), b)

	for ; i > 0; i-- {
		r.Exec()
	}

	c.Status(http.StatusOK)
}

//
func (a *GoTags) deleteAccount(c *gin.Context) {
	var d struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	password := d.Password

	user := c.GetInt("user")
	// if user == 0 {
	// 	c.Status(http.StatusUnauthorized)
	// 	return
	// }

	var passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT password_hash FROM users WHERE id = $1;`,
		user)
	err := row.Scan(&passwordHash)

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	_, err = a.pool.Exec(
		context.Background(),
		`DELETE FROM users WHERE id = $1;`, user)
	if err != nil {
		c.Status(http.StatusInternalServerError)
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
