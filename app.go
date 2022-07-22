package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/jackc/pgconn"
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

// GoTags holds parts together
type GoTags struct {
	pool       *pgxpool.Pool
	router     *gin.Engine
	authorized *gin.RouterGroup
	mailer     mailer
}

// Session is set to gin context once Token validates
type Session struct {
	User  int
	Token string
}

// auth middleware. Token is http header variable with format "Token": "uuid-v4".
// Sessions are stored in database.
func (a *GoTags) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokens, ok := c.Request.Header["Token"]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// use the first value
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

		// c.Set("user", user)
		c.Set("session", Session{user, token})
		c.Next()
	}
}

// session helper
func currentSession(c *gin.Context) Session {
	s, ok := c.Get("session")
	if !ok {
		log.Fatalln("currentSession: no session")
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
	log.Println("Running database cleanup")

	b := &pgx.Batch{}
	b.Queue(fmt.Sprintf(`DELETE FROM pending WHERE created_at < now() - interval '%s';`, pendingTTL))
	b.Queue(fmt.Sprintf(`DELETE FROM sessions WHERE modified_at < now() - interval '%s';`, sessionTTL))

	// TODO: cleanup limiter

	r := a.pool.SendBatch(context.Background(), b)
	defer r.Close()

	_, err := r.Exec()
	if err != nil {
		log.Println("Error in database cleanup:", err)
	}
	_, err = r.Exec()
	if err != nil {
		log.Println("Error in database cleanup:", err)
	}
}

// called from main, runs the server in a loop.
func (a *GoTags) run(server string) {
	a.router.Run(server)
}

// ******************************************************************
func queryEmailExists(pool *pgxpool.Pool, email string) (bool, error) {
	var exists bool
	row := pool.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		email)
	err := row.Scan(&exists)
	return exists, err
}

func queryEmailExistsTx(tx pgx.Tx, email string) (bool, error) {
	var exists bool
	row := tx.QueryRow(
		context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);`,
		email)
	err := row.Scan(&exists)
	return exists, err
}

func queryProfileDataTx(tx pgx.Tx, user int) (data map[string]any, modifiedAt time.Time, err error) {
	row := tx.QueryRow(
		context.Background(),
		`SELECT data, modified_at FROM profiles WHERE id = $1;`,
		user)
	err = row.Scan(&data, &modifiedAt)
	return data, modifiedAt, err
}

type tagrow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	Modified  string `json:"modified"`
	Connected string `json:"connected"`
	Accessed  string `json:"accessed"`
	ActedOn   string `json:"acted_on"`
}

type byConnected []tagrow

func (t byConnected) Len() int {
	return len(t)
}
func (t byConnected) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}
func (t byConnected) Less(i, j int) bool {
	ti := t[i].Connected
	tj := t[j].Connected
	return ti < tj
}

func queryTagsTx(tx pgx.Tx, user int) ([]tagrow, error) {
	rows, err := tx.Query(
		context.Background(),
		`SELECT t.id, t.name, t.category, t.modified_at, te.category, te.event_at
		 FROM tag_events te INNER JOIN tags t ON tag_id = id
		 WHERE user_id = $1;`,
		user)
	defer rows.Close()

	tagmap := map[string]tagrow{}
	for rows.Next() {
		var id, name, category, modified, event, eventAt string
		err = rows.Scan(&id, &name, &category, &modified, &event, &eventAt)
		if err == nil {
			if _, ok := tagmap[id]; !ok {
				tagmap[id] = tagrow{}
			}
			t := tagmap[id]
			t.ID = id
			t.Name = name
			t.Modified = modified
			t.Category = category

			switch event {
			case "connected":
				t.Connected = eventAt
			case "accessed":
				t.Accessed = eventAt
			case "acted_on":
				t.ActedOn = eventAt
			default:
				log.Fatal("unexpected tag event", event)
			}
		} else {
			return nil, err
		}
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	rows.Close()

	tagrows := make([]tagrow, 0, len(tagmap))
	for k := range tagmap {
		tagrows = append(tagrows, tagmap[k])
	}

	// sort first connected tag first
	sort.Sort(byConnected(tagrows))

	return tagrows, nil
}

func (a *GoTags) queryUserDataTx(tx pgx.Tx, user int) (map[string]any, error) {
	profileData, m, err := queryProfileDataTx(tx, user)
	if err != nil {
		return nil, err
	}
	tags, err := queryTagsTx(tx, user)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"profile": map[string]any{
			"data":        profileData,
			"modified_at": m,
		},
		"tags": tags,
	}, nil
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

	// check if email is in use
	exists, err := queryEmailExists(a.pool, email)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case exists:
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
		Password string `json:"password" binding:"required,min=1"`
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

	// begin transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// check if email in use
	exists, err := queryEmailExistsTx(tx, email)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case exists:
		c.Status(http.StatusConflict)
		return
	}

	// calculate hash from incoming password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"name":          name,
		"password_hash": string(passwordHash),
		"extra":         extra,
	}

	// add email to limiter
	t, err := tx.Exec(
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
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
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
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusTooManyRequests)
		return
	case err != nil:
		switch e := err.(type) {
		case *pgconn.PgError:
			if e.Code == "P0001" && e.Message == "pending: no capacity" {
				c.Status(http.StatusTooManyRequests)
				return
			}
		default:
			c.Status(http.StatusInternalServerError)
			return
		}
	}

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

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) joinActivate(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required,uuid"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=1"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	id := d.ID
	password := d.Password

	// begin transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// delete matching pending join, get email and data
	var email string
	data := map[string]any{}
	row := tx.QueryRow(
		context.Background(),
		`DELETE FROM pending WHERE id = $1 AND category = 'join' RETURNING email, data;`,
		id)
	err = row.Scan(&email, &data)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusNotFound)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
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
	switch {
	case err == pgx.ErrNoRows:
		// should not happen
		c.Status(http.StatusInternalServerError)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	var token string
	row = tx.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user)
	err = row.Scan(&token)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusTooManyRequests)
		return
	case err != nil:
		switch e := err.(type) {
		case *pgconn.PgError:
			if e.Code == "P0001" && e.Message == "sessions: no capacity" {
				c.Status(http.StatusTooManyRequests)
				return
			}
		default:
			c.Status(http.StatusInternalServerError)
			return
		}
	}

	userData, err := a.queryUserDataTx(tx, user)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

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

	// begin transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// get use data and profile
	var user int
	var data map[string]any
	var name, passwordHash string
	row := tx.QueryRow(
		context.Background(),
		`WITH xu AS (
			SELECT id, name, password_hash FROM users WHERE email = $1
		 )
		 SELECT u.id, name, password_hash, data FROM profiles AS p JOIN xu AS u ON p.id = u.id;`,
		email)
	err = row.Scan(&user, &name, &passwordHash, &data)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusUnauthorized)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		c.Status(http.StatusUnauthorized)
		return
	}

	// create a session
	var token string
	row = tx.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id)
			VALUES ($1)
			RETURNING id;`,
		user)
	err = row.Scan(&token)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusTooManyRequests)
		return
	case err != nil:
		switch e := err.(type) {
		case *pgconn.PgError:
			if e.Code == "P0001" && e.Message == "sessions: no capacity" {
				c.Status(http.StatusTooManyRequests)
				return
			}
		default:
			c.Status(http.StatusInternalServerError)
			return
		}
	}

	userData, err := a.queryUserDataTx(tx, user)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

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

	// beging transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// get user with matching email
	var user int
	row := tx.QueryRow(
		context.Background(),
		`SELECT id FROM users WHERE email = $1;`,
		email)
	err = row.Scan(&user)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusNotFound)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// add email to limiter
	t, err := tx.Exec(
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
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
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
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusTooManyRequests)
		return
	case err != nil:
		switch e := err.(type) {
		case *pgconn.PgError:
			if e.Code == "P0001" && e.Message == "pending: no capacity" {
				c.Status(http.StatusTooManyRequests)
				return
			}
		default:
			c.Status(http.StatusInternalServerError)
			return
		}
	}
	// switch {
	// case err == pgx.ErrNoRows:
	// 	c.Status(http.StatusTooManyRequests)
	// 	return
	// case err != nil:
	// 	c.Status(http.StatusInternalServerError)
	// 	return
	// }

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

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusCreated)
}

//
func (a *GoTags) newPassword(c *gin.Context) {
	var d struct {
		ID       string `json:"id" binding:"required,uuid"`
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
	defer tx.Rollback(context.Background())

	// delete matching pending password reset, get email
	var email string
	row := tx.QueryRow(
		context.Background(),
		`DELETE FROM pending WHERE id = $1 AND category = 'reset_password' RETURNING email;`,
		id)
	err = row.Scan(&email)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusNotFound)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
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
	row = tx.QueryRow(
		context.Background(),
		`UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id, name;`,
		passwordHash, email)
	err = row.Scan(&user, &name)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// create session token
	var token string
	row = tx.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`,
		user)
	err = row.Scan(&token)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusTooManyRequests)
		return
	case err != nil:
		switch e := err.(type) {
		case *pgconn.PgError:
			if e.Code == "P0001" && e.Message == "sessions: no capacity" {
				c.Status(http.StatusTooManyRequests)
				return
			}
		default:
			c.Status(http.StatusInternalServerError)
			return
		}
	}

	userData, err := a.queryUserDataTx(tx, user)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
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

	t, err := a.pool.Exec(
		context.Background(),
		`UPDATE sessions SET modified_at = $1 WHERE id = $2;`,
		time.Now(), session.Token)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	}

	c.Status(http.StatusOK)
}

//
func (a *GoTags) deleteSession(c *gin.Context) {
	session := currentSession(c)

	t, err := a.pool.Exec(
		context.Background(),
		`DELETE FROM sessions WHERE id = $1;`,
		session.Token)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	}
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
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
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

	var newName string
	row := a.pool.QueryRow(
		context.Background(),
		`UPDATE users SET name = $1
			WHERE id = $2 
			RETURNING name;`,
		name, session.User)
	err := row.Scan(&newName)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
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

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	var email string
	var passwordHash string
	row := tx.QueryRow(
		context.Background(),
		`SELECT email, password_hash FROM users WHERE id = $1;`,
		session.User)
	err = row.Scan(&email, &passwordHash)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// validate password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if email != d.Email || err != nil {
		c.Status(http.StatusConflict)
		return
	}

	t, err := a.pool.Exec(
		context.Background(),
		`DELETE FROM users WHERE id = $1;`, session.User)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusNoContent)
}

//
func (a *GoTags) getData(c *gin.Context) {
	session := currentSession(c)

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	data, err := a.queryUserDataTx(tx, session.User)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, data)
}

//
func (a *GoTags) updateProfile(c *gin.Context) {
	session := currentSession(c)

	var d struct {
		Profile    map[string]any `json:"profile" binding:"required"`
		ModifiedAt string         `json:"modified_at" binding:"required,datetime=2006-01-02T15:04:05Z07:00"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	t, err := tx.Exec(
		context.Background(),
		`UPDATE profiles SET data = $1
			WHERE id = $2 AND modified_at = $3;`,
		d.Profile, session.User, d.ModifiedAt)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusConflict)
		return
	}

	data, err := a.queryUserDataTx(tx, session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, data)
}

//
func (a *GoTags) connectTags(c *gin.Context) {
	session := currentSession(c)

	var d struct {
		Tags []string `json:"tags" binding:"gt=0,dive,uuid"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	user := session.User
	tags := d.Tags

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	b := &pgx.Batch{}

	for _, t := range tags {
		b.Queue(`INSERT INTO tag_event (user_id, tag_id, category, event_at)
				 VALUES ($1, $2, 'connected', current_timestamp)
				 ON CONFLICT (user_id, tag_id, category, event_at) DO UPDATE
				 SET event_at=EXCLUDED.event_at;`, user, t)
	}

	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	for range tags {
		t, err := r.Exec()
		switch {
		case t.RowsAffected() == 0:
			c.Status(http.StatusNotFound)
			return
		case err != nil:
			c.Status(http.StatusInternalServerError)
			return
		}
	}
	r.Close()

	data, err := a.queryUserDataTx(tx, session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, data)
}

//
func (a *GoTags) disconnectTags(c *gin.Context) {
	session := currentSession(c)

	var d struct {
		Tags []string `json:"tags" binding:"gt=0,dive,uuid"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	user := session.User
	tags := d.Tags

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(
		context.Background(),
		`DELETE FROM tag_events WHERE user_id = $1 AND tag_id IN $2`, user, tags)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
		// case t.RowsAffected() == 0:
		// 	c.Status(http.StatusGone)
		// 	return
	}

	data, err := a.queryUserDataTx(tx, session.User)
	if err != nil {
		c.Status(http.StatusGone)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, data)
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

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// get current password hash
	var hash string
	row := tx.QueryRow(
		context.Background(),
		`SELECT password_hash FROM users WHERE id = $1;`,
		session.User)
	err = row.Scan(&hash)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
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
	t, err := tx.Exec(
		context.Background(),
		`UPDATE users SET password_hash = $1 WHERE id = $2;`, newHash, session.User)
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	}

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusOK)
}

type tagPath struct {
	ID string `uri:"id" binding:"required,uuid"`
}

//
func (a *GoTags) getTag(c *gin.Context) {
	session := currentSession(c)

	var tp tagPath
	if err := c.ShouldBindUri(&tp); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	tag := tp.ID

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	var name, category string
	var data map[string]any
	var modifiedAt time.Time

	b := &pgx.Batch{}

	// 1
	b.Queue(`SELECT name, category, data, modified_at FROM tags WHERE id = $1;`, tag)

	// 2
	b.Queue(`INSERT INTO tag_events (user_id, tag_id, category, event_at)
	         VALUES ($1, $2, 'accessed', current_timestamp)
			 ON CONFLICT (user_id, tag_id, category) DO UPDATE
			 SET event_at=EXCLUDED.event_at;`, session.User, tag)
	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	// 1
	row := r.QueryRow()
	err = row.Scan(&name, &category, &data, &modifiedAt)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusNotFound)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// 2
	t, err := r.Exec()
	switch {
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}
	r.Close()

	// commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":        name,
		"category":    category,
		"data":        data,
		"modified_at": modifiedAt,
	})
}

type tagFunc func(currentData, updateData map[string]any) (newData map[string]any)

func nopHandler(currentData, updateData map[string]any) map[string]any {
	return updateData
}

var tagHandlers = map[string]tagFunc{
	"nop": nopHandler,
	// "counter": nil,
	// "anti-counter": nil,
}

func (a *GoTags) updateTag(c *gin.Context) {
	session := currentSession(c)

	var tp tagPath
	if err := c.ShouldBindUri(&tp); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	tag := tp.ID

	var d struct {
		Data map[string]any `json:"data" binding:"required"`
	}
	if err := c.BindJSON(&d); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	updateData := d.Data

	// start transaction
	tx, err := a.pool.Begin(context.Background())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// query tag data
	var name, category string
	var currentData map[string]any
	row := tx.QueryRow(
		context.Background(),
		`SELECT name,category,data FROM tags WHERE id = $1;`, tag)
	err = row.Scan(&name, &category, &currentData)
	switch {
	case err == pgx.ErrNoRows:
		c.Status(http.StatusNotFound)
		return
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	}

	// use tag category to call correct tag handler
	f, ok := tagHandlers[category]
	if !ok {
		log.Println("unexpected tag handler category", category)
		c.Status(http.StatusInternalServerError)
		return
	}
	newData := f(currentData, updateData)

	b := &pgx.Batch{}

	b.Queue(`UPDATE tags SET data = $1 WHERE id = $2;`, newData, tag)

	b.Queue(`INSERT INTO tag_events (user_id, tag_id, category, event_at)
			 VALUES ($1, $2, 'acted_on', current_timestamp)
			 ON CONFLICT (user_id, tag_id, category) DO UPDATE
			 SET event_at=EXCLUDED.event_at;`, session.User, tag)

	r := tx.SendBatch(context.Background(), b)
	defer r.Close()

	t, err := r.Exec()
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
		c.Status(http.StatusGone)
		return
	}

	t, err = r.Exec()
	switch {
	case err != nil:
		c.Status(http.StatusInternalServerError)
		return
	case t.RowsAffected() == 0:
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
	c.JSON(http.StatusOK, gin.H{
		"data": newData,
	})
}
