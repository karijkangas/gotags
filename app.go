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
	pendingTTL       = "1 days"
	sessionTTL       = "30 days"
)

var paths = map[string]string{
	"joinCheck":     "/api/join/check",
	"join":          "/api/join",
	"joinActivate":  "/api/join/activate",
	"signin":        "/api/signin",
	"resetPassword": "/api/reset-password",
	"newPassword":   "/api/reset-password/new",
	//
	"auth":              "",
	"auth_session":      "/api/auth/session",
	"auth_account":      "/api/auth/account",
	"auth_data":         "/api/auth/your-data",
	"auth_data_profile": "/api/auth/your-data/profile",
	"auth_data_tags":    "/api/auth/your-data/tags",
	"auth_password":     "/api/auth/password",
	"auth_tags":         "/api/auth/tags/:id",
	//
	"debug_reset":   "/debug/reset",
	"debug_pending": "/debug/pending",
}

// GoTags holds all
type GoTags struct {
	pool       *pgxpool.Pool
	router     *gin.Engine
	authorized *gin.RouterGroup
	mailer     mailer
}

// Session is set to gin context once Token validates
type Session struct {
	User int
	// Name  string
	// Email string
	Token string
}

// // default profile
// func defaultProfile() map[string]any {
// 	return map[string]any{}
// }

// auth middleware. Token is http header variable with format "Token": "uuid-v4".
// Sessions are stored in database.
func (a *GoTags) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokens, ok := c.Request.Header["Token"]
		if !ok {
			fmt.Println("STEP 1")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// always just the first value
		token := tokens[0]
		var user int
		// var name, email string // excluding password_hash.
		err := a.pool.QueryRow(
			context.Background(),
			`SELECT (user_id) FROM sessions WHERE id = $1;`,
			token).Scan(&user)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Set("session", Session{user, token})
		c.Next()
	}
}

// session helper
func currentSession(c *gin.Context) Session {
	s, ok := c.Get("session")
	if !ok {
		panic("no session")
	}
	return s.(Session)
}

// hook
var extraInitializations = []func(a *GoTags){}

func addExtraInitialization(f func(a *GoTags)) {
	extraInitializations = append(extraInitializations, f)
}

/* initialize connects to database, sets up gin router and initializes (a *GoTags).
It also activate hooks and the scheduler. CALLED from main. */
func (a *GoTags) initialize(databaseURL string) {
	pool, err := pgxpool.Connect(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	router := gin.Default()

	router.POST(paths["joinCheck"], a.joinCheck)
	router.POST(paths["join"], a.join)
	router.POST(paths["joinActivate"], a.joinActivate)
	router.POST(paths["signin"], a.signin)
	router.POST(paths["resetPassword"], a.resetPassword)
	router.POST(paths["newPassword"], a.newPassword)

	authorized := router.Group(paths["auth"])
	authorized.Use(a.auth())
	{
		authorized.PATCH(paths["auth_session"], a.renewSession)
		authorized.DELETE(paths["auth_session"], a.deleteSession)
		authorized.GET(paths["auth_account"], a.getAccount)
		authorized.PUT(paths["auth_account"], a.updateAccount)
		authorized.DELETE(paths["auth_account"], a.deleteAccount)
		authorized.GET(paths["auth_data"], a.getData)
		authorized.POST(paths["auth_data_profile"], a.updateProfile)
		authorized.POST(paths["auth_data_tags"], a.connectTags)
		authorized.DELETE(paths["auth_data_tags"], a.disconnectTags)
		authorized.POST(paths["auth_password"], a.updatePassword)
		authorized.GET(paths["auth_tags"], a.getTag)
		authorized.PUT(paths["auth_tags"], a.updateTag)
	}

	a.pool = pool
	a.router = router
	a.authorized = authorized
	a.mailer = sasMailer

	// hook run hooks
	for _, f := range extraInitializations {
		f(a)
	}

	// start scheduler; initially to run nightly database cleanup
	s := gocron.NewScheduler(time.UTC)
	s.Every(1).Day().At(cleanupDBTimeUTC).Do(a.cleanupDB)
	s.StartAsync()
}

// cleanup runs database cleanup
func (a *GoTags) cleanupDB() {
	log.Printf("Running database cleanup")

	b := &pgx.Batch{}
	b.Queue(fmt.Sprintf(`DELETE FROM pending WHERE created_at < now() - interval '%s';`, pendingTTL))
	b.Queue(fmt.Sprintf(`DELETE FROM sessions WHERE modified_at < now() - interval '%s';`, sessionTTL))
	// TODO: cleanup limiter
	r := a.pool.SendBatch(context.Background(), b)

	r.Exec()
	r.Exec()
	r.Close()
}

// called from main, runs the server in a loop.
func (a *GoTags) run(server string) {
	a.router.Run(server)
}

// ******************************************************************
func (a *GoTags) queryEmailExists(email string) (bool, error) {
	var exists bool
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		email)
	err := row.Scan(&exists)

	return exists, err
}

func (a *GoTags) queryProfileData(user int) (data map[string]any, err error) {
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT data FROM profiles WHERE id = $1;`,
		user)
	err = row.Scan(&data)
	return data, err
}

//
// func (a *GoTags) queryData(user int) map[string]any {
// 	var data map[string]any
// 	row, err := a.pool.Query(
// 		context.Background(),
// 		`SELECT (name, email) FROM users WHERE id = $1;`,
// 		// `SELECT data FROM profiles WHERE id = $1;`,
// 		user)
// 	err = row.Scan(&data)
// 	if err != nil {
// 		return nil
// 	}
// 	return data
// }

//
func (a *GoTags) queryUserData(user int) (map[string]any, error) {
	profileData, err := a.queryProfileData(user)
	return map[string]any{
		"profile": profileData,
		"tags":    [][4]string{},
	}, err
	// var tags []string
	// userTags, err := tx.Query(
	// 	context.Background(),
	// 	`SELECT (tag_id, event_at) FROM tag_events
	// 	 WHERE user_id = $1 AND category == 'connected'
	// 	 ORDER BY event_at ASC;`,
	// 	user)

	// accessed := tx.QueryRow(
	// 	context.Background(),
	// 	`SELECT (tag_id, event_at) FROM tag_events
	// 	 WHERE user_id = $1 AND category == 'accessed'
	// 	 ORDER BY event_at DESC
	// 	 LIMIT 1;`,
	// 	user)

	// actedOn, err = tx.QueryRow(
	// 	context.Background(),
	// 	`SELECT (tag_id, event_at) FROM tag_events
	// 	 WHERE user_id = $1 AND category == 'acted_on'
	// 	 ORDER BY event_at DESC
	// 	 LIMIT 1;`,
	// 	user)
}

// ******************************************************************
// paths
func (a *GoTags) joinCheck(c *gin.Context) {
	var d struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	email := d.Email

	// ensure email is not in use
	exists, err := a.queryEmailExists(email)
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
func (a *GoTags) join(c *gin.Context) {
	var d struct {
		Name     string `json:"name" binding:"required,min=1"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=3"`
		Lang     string `json:"lang"`
		Extra    any    `json:"extra"`
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

	// ensure email not in use
	exists, err := a.queryEmailExists(email)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if exists {
		c.Status(http.StatusConflict)
		return
	}

	// calculate hash from incoming password
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

	// beging transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// add email to limiter
	_, err = tx.Exec(
		context.Background(),
		`INSERT INTO limiter (email, counter)
		 SELECT $1, counter_nr
		 FROM (
	   		SELECT counter_nr
	   		FROM   generate_series (1, get_emails_limit()) counter_nr
	   		EXCEPT (SELECT counter FROM limiter WHERE email = $1)
	   		ORDER  BY 1
	   		LIMIT  1
	   	 ) sub;`, email)
	if err != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}

	var uuid string
	row := tx.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, data)
			VALUES ($1, 'join', $2)
			RETURNING id;`,
		email, data)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}
	err = tx.Commit(context.Background())
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
func (a *GoTags) joinActivate(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required,min=1"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background()) // safe to call after commit

	// delete matching pending join, get email and data
	var email string
	data := map[string]any{}
	row := tx.QueryRow(
		context.Background(),
		`DELETE FROM pending WHERE id = $1 AND category = 'join' RETURNING email, data;`,
		id)
	err = row.Scan(&email, &data)
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

	// comment out as long as defaultProfile is empty JSON object, a database default
	// profile := defaultProfile()
	// var newProfile map[string]any

	var token string
	err2 := tx.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user).Scan(&token)
	if err2 != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}

	// // insert session and profile
	// // var token string
	// b := &pgx.Batch{}
	// b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	// // b.Queue(`WITH ins AS(
	// // 			INSERT INTO profiles (id, data)
	// // 		   	VALUES ($1, $2)
	// // 			ON CONFLICT(id) DO UPDATE
	// // 			SET data = EXCLUDED.data
	// // 			RETURNING data
	// // 		)
	// // 		SELECT * FROM ins
	// // 		UNION
	// // 			SELECT data FROM profiles WHERE id=$1;`, user, profile)
	// b.Queue(`SELECT data FROM profiles WHERE id=$1;`, user)
	// r := tx.SendBatch(context.Background(), b)
	// defer r.Close()
	// err2 := r.QueryRow().Scan(&token) // insert session
	// // err3 := r.QueryRow().Scan(&newProfile) // insert profile

	// if err2 != nil {
	// 	c.Status(http.StatusTooManyRequests)
	// 	return
	// }

	// if err3 != nil {
	// 	c.Status(http.StatusInternalServerError)
	// 	return
	// }
	// r.Close()

	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	userData, err := a.queryUserData(user)

	// c.JSON(http.StatusOK, gin.H{"name": name, "email": email, "": newProfile, "token": token, "extra": extra})
	c.JSON(http.StatusOK, gin.H{
		"name":  name,
		"email": email,
		"data":  userData,
		"token": token,
		"extra": extra,
	})
}

//
func (a *GoTags) signin(c *gin.Context) {
	var d struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
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
		c.Status(http.StatusTooManyRequests)
		return
	}

	userData, err := a.queryUserData(user)

	c.JSON(http.StatusOK, gin.H{
		"name":  name,
		"email": email,
		"data":  userData,
		"token": token,
	})
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

	// get user with matching email
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

	// beging transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// add email to limiter
	_, err = tx.Exec(
		context.Background(),
		`INSERT INTO limiter (email, counter)
		 SELECT $1, counter_nr
		 FROM (
	   		SELECT counter_nr
	   		FROM   generate_series (1, get_emails_limit()) counter_nr
	   		EXCEPT (SELECT counter FROM limiter WHERE email = $1)
	   		ORDER  BY 1
	   		LIMIT  1
	   	 ) sub;`, email)
	if err != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}

	// add pending reset password data
	var uuid string
	row = tx.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category)
			VALUES ($1, 'reset_password')
			RETURNING id;`,
		email)
	err = row.Scan(&uuid)
	if err != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}

	err = tx.Commit(context.Background())
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
		ID       string `json:"id" binding:"required,min=1"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background()) // safe to call after commit

	// delete matching pending password reset, get email
	var email string
	row := tx.QueryRow(
		context.Background(),
		`DELETE FROM pending WHERE id = $1 AND category = 'reset_password' RETURNING email;`,
		id)
	err = row.Scan(&email)
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

	// update password hash, get user id and name
	var user int
	var name string
	err = tx.QueryRow(
		context.Background(),
		`UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id, name;`,
		passwordHash, email).Scan(&user, &name)

	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	// create session token
	var token string
	err2 := tx.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`,
		user).Scan(&token)

	// if err2 != nil {
	// 	c.Status(http.StatusGone)
	// 	return
	// }

	// // creater session and profile
	// b := &pgx.Batch{}
	// b.Queue(`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	// // b.Queue(`SELECT data FROM profiles WHERE id = $1;`, user)
	// r := tx.SendBatch(context.Background(), b)
	// defer r.Close()

	// // var token string
	// // var profile map[string]any

	// err1 := r.QueryRow().Scan(&token)
	// // err2 := r.QueryRow().Scan(&profile)

	if err2 != nil {
		c.Status(http.StatusTooManyRequests)
		return
	}
	// if err2 != nil {
	// 	c.Status(http.StatusGone)
	// 	return
	// }
	// r.Close()

	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	userData, err := a.queryUserData(user)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":  name,
		"email": email,
		"data":  userData,
		"token": token})
}

//
func (a *GoTags) renewSession(c *gin.Context) {
	session := currentSession(c)

	_, err := a.pool.Exec(
		context.Background(),
		`UPDATE sessions SET modified_at = $1 WHERE id = $2;`,
		time.Now(), session.Token)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.Status(http.StatusOK)
}

//
func (a *GoTags) deleteSession(c *gin.Context) {
	session := currentSession(c)

	a.pool.Exec(
		context.Background(),
		`DELETE FROM sessions WHERE id = $1;`,
		session.Token)
	c.Status(http.StatusNoContent)
}

//
func (a *GoTags) getAccount(c *gin.Context) {
	session := currentSession(c)

	var name string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT name FROM users WHERE id = $1;`,
		session.User)
	err := row.Scan(&name)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"name": name})
}

//
func (a *GoTags) updateAccount(c *gin.Context) {
	session := currentSession(c)

	var d struct {
		Name string `json:"name" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	name := d.Name

	row := a.pool.QueryRow(
		context.Background(),
		`UPDATE users SET name = $1
			WHERE id = $2 
			RETURNING name;`,
		name, session.User)
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
	session := currentSession(c)

	var d struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	password := d.Password

	var email string
	var passwordHash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT email, password_hash FROM users WHERE id = $1;`,
		session.User)
	err := row.Scan(&email, &passwordHash)

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if email != d.Email || err != nil {
		c.Status(http.StatusConflict)
		return
	}

	_, err = a.pool.Exec(
		context.Background(),
		`DELETE FROM users WHERE id = $1;`, session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusNoContent)
}

//
func (a *GoTags) getData(c *gin.Context) {
	session := currentSession(c)

	data, err := a.queryUserData(session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	// c.JSON(http.StatusOK, gin.H{"data": data})
	c.JSON(http.StatusOK, data)
}

//
func (a *GoTags) updateProfile(c *gin.Context) {
	session := currentSession(c)
	// id := c.GetInt("user")

	data, err := a.queryProfileData(session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

//
func (a *GoTags) connectTags(c *gin.Context) {
	session := currentSession(c)
	// id := c.GetInt("user")

	data, err := a.queryProfileData(session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

//
func (a *GoTags) disconnectTags(c *gin.Context) {
	session := currentSession(c)
	// id := c.GetInt("user")

	data, err := a.queryProfileData(session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

//
func (a *GoTags) updatePassword(c *gin.Context) {
	session := currentSession(c)

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
	// user := c.GetInt("user")

	// get current password hash
	var hash string
	row := a.pool.QueryRow(
		context.Background(),
		`SELECT password_hash FROM users WHERE id = $1;`,
		session.User)
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
	_, err = a.pool.Exec(
		context.Background(),
		`UPDATE users SET password_hash = $1 WHERE id = $2;`, newHash, session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusOK)
}

//
func (a *GoTags) getTag(c *gin.Context) {
	// session := currentSession(c)
	id := c.Param("id")

	// TODO: tag data

	c.JSON(http.StatusOK, gin.H{"tag": id})
}

func (a *GoTags) updateTag(c *gin.Context) {
	// session := currentSession(c)
	id := c.Param("id")

	// TODO: tag data

	c.JSON(http.StatusOK, gin.H{"tag": id})
}
