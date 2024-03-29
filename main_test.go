package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const databaseURL = "postgres://gotags:gotags@localhost:5432/gotags_test"

func TestMain(m *testing.M) {
	app.initialize(databaseURL)

	// make test preparations; mock emailer and validator
	emailer := app.emailer
	app.emailer = testEmailer
	defer func() {
		app.emailer = emailer
	}()
	resetEmailer()

	emailValidator := app.emailValidator
	app.emailValidator = testEmailValidator
	defer func() {
		app.emailValidator = emailValidator
	}()
	resetEmailValidator()

	code := m.Run()
	os.Exit(code)
}

// ******************************************************************
func TestJoinCheck(t *testing.T) {
	clearTables(t, "users")

	for _, email := range []string{
		"johndoe@example.com",
		longEmail(0),
	} {
		din1 := map[string]string{
			"email": email,
		}
		response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, din1)), "")
		checkResponseCode(t, response, http.StatusOK)

		var dout1 joinCheckOut
		err := json.Unmarshal(response.Body.Bytes(), &dout1)
		if err != nil {
			t.Fatalf("failed to unmarshall data: %s", err)
		}
		if dout1.Email != email {
			t.Fatalf("unexpected data. Got %s. Want %s", dout1.Email, email)
		}
	}
}

func TestJoinCheckFails(t *testing.T) {
	clearTables(t, "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// existing user
	din1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")
}

func TestJoinCheckBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                   // no email
		{`{"foo": 123}`, 400},         // no email
		{`{"email": ""}`, 400},        // empty email
		{`{"email": "foo@bar"}`, 400}, // invalid email
		{fmt.Sprintf(`{"email": "%s"}`, longEmail(1)), 400}, // too long email
		// {fmt.Sprintf(`{"email": "%s"}`, longEmail(0)), 400}, // ok
	}

	for _, din := range data {
		response := doPost(t, paths["joinCheck"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

func TestJoinCheckValidatorYes(t *testing.T) {
	clearTables(t, "users")
	resetEmailValidator()

	email := "johndoe@example.com"

	din1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertValidator(t, resetEmailValidator(), email)
}

func TestJoinCheckValidatorNo(t *testing.T) {
	clearTables(t, "users")

	setEmailValidator(false)
	defer resetEmailValidator()

	email := "johndoe@example.com"

	din1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusConflict)

	assertValidator(t, resetEmailValidator(), email)
}

// ******************************************************************
func TestJoin(t *testing.T) {
	clearTables(t)
	resetEmailer()

	data := []map[string]string{
		{
			"name":     "John Doe",
			"email":    "johndoe@example.com",
			"password": "password1234",
		},
		{
			"name":     "John Doe",
			"email":    "johndoe@example.com",
			"password": "password1234",
			"lang":     "en",
			"extra":    "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8",
		},
		{
			"name":     longString(0),
			"email":    longEmail(0),
			"password": longString(0),
			"lang":     longString(0),
			"extra":    longString(0),
		},
	}

	for i, din := range data {
		name1, email1, password1, lang1, extra1 := din["name"], din["email"], din["password"], din["lang"], din["extra"]

		response := doPost(t, paths["join"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")

		id2, name2, email2, hash2, extra2 := getPendingJoin(t, i)

		if name2 != name1 || email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected data. Got %s, %s, %s. Want %s, %s, %s", name1, email1, extra1, name2, email2, extra2)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash %s", hash2)
		}
		assertMailer(t, resetEmailer(), id2, email2, lang1)
	}
}

func TestJoinMultiple(t *testing.T) {
	clearTables(t)

	var data = []map[string]string{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password2",
		"lang":     "en",
		"extra":    "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8",
	}, {
		"name":     "John Smith",
		"email":    "johnsmith@example.com",
		"password": "password3",
		"extra":    "https://gotagsavaruus.com/tags/bf72f74b-6dbc-4d94-9b99-26413b3085e9",
	}, {
		"name":     "John Doe 3",
		"email":    "johndoe@example.com",
		"password": "password4",
	}}

	for i, din := range data {
		name1, email1, password1, _, extra1 := din["name"], din["email"], din["password"], din["lang"], din["extra"]

		response := doPost(t, paths["join"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")

		_, name2, email2, hash2, extra2 := getPendingJoin(t, i)

		if name2 != name1 || email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected data. Got %s, %s, %s. Want %s, %s, %s",
				name2, email2, extra2, name1, email1, extra1)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash %s", hash2)
		}
	}
}

func TestJoinFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	din1 := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
	}
	addUser(t, name, email, password)

	// existing user
	response := doPost(t, paths["join"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 0)
}

func TestJoinBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@b.com", "password": "123"}`, 400},                                                            // no name
		{`{"name":"", "email": "a@b.com", "password": "123"}`, 400},                                                 // empty name
		{`{"name":"John", "password": "123"}`, 400},                                                                 // no email
		{`{"name":"John", "email": "", "password": "123"}`, 400},                                                    // empty email
		{`{"name":"John", "email": "abc", "password": "123"}`, 400},                                                 // invalid email
		{`{"name":"John", "email": "a@b.com"}`, 400},                                                                // no password
		{`{"name":"John", "email": "a@b.com", "password": ""}`, 400},                                                // empty password
		{`{"name":"John", "email": "a@b.com", "password": "123", "extra": }`, 400},                                  // invalid extra
		{`{"name":"John", "email": "a@b.com", "password": "123", "extra": {] }`, 400},                               // invalid extra
		{fmt.Sprintf(`{"name":"%s", "email": "a@b.com", "password": "123" }`, longString(1)), 400},                  // too long name
		{fmt.Sprintf(`{"name":"John", "email": "%s", "password": "123" }`, longEmail(1)), 400},                      // too long email
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "%s" }`, longString(1)), 400},                 // too long password
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "lang": "%s" }`, longString(1)), 400},  // too long lang
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "extra": "%s" }`, longString(1)), 400}, // too long extra
		// {fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "lang": "en", "extra": "yes" }`), 400},             // ok
	}

	for _, din := range data {
		response := doPost(t, paths["join"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

func TestJoinValidatorYes(t *testing.T) {
	clearTables(t)
	resetEmailer()
	resetEmailValidator()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	din1 := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	assertValidator(t, resetEmailValidator(), email)
}

func TestJoinValidatorNo(t *testing.T) {
	clearTables(t)
	resetEmailer()

	setEmailValidator(false)
	defer resetEmailValidator()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	din1 := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")

	assertValidator(t, resetEmailValidator(), email)
}

// ******************************************************************
func TestJoinActivate(t *testing.T) {
	clearTables(t)

	data := []map[string]string{
		{
			"name":     "John Doe",
			"email":    "johndoe1@example.com",
			"password": "password1234",
		},
		{
			"name":     "John Doe",
			"email":    "johndoe2@example.com",
			"password": "password1234",
			"extra":    "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8",
		},
	}

	for i, din := range data {
		name1, email1, password1, extra1 := din["name"], din["email"], din["password"], din["extra"]

		id := addPendingJoin(t, name1, email1, password1, extra1)
		din["id"] = id

		response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusOK)

		assertPendingJoinCount(t, 0)
		assertUserCount(t, i+1)
		assertProfileCount(t, i+1)
		assertSessionCount(t, i+1)

		user, _, hash2 := getUser(t, email1)
		session := getSession(t, user)

		var dout joinActivateOut
		err := json.Unmarshal(response.Body.Bytes(), &dout)
		if err != nil {
			t.Fatalf("failed to unmarshall data: %s", err)
		}

		name2, email2, token2, extra2 := dout.Name, dout.Email, dout.Token, dout.Extra

		if name2 != name1 || email2 != email1 || token2 != session || extra2 != extra1 {
			t.Fatalf("unexpected data. Got %s, %s, %s, %s. Want %s, %s, %s, %s", name2, email2, token2, extra2, name1, email1, session, extra1)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash %s", hash2)
		}
		assertUserData(t, dout.Data, defaultUserData())
	}
}

func TestJoinActivateExisting(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"
	extra1 := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"
	profile1 := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	// create user with name, email and password, update profile
	user := addUser(t, name1, email1, password1)
	updateProfile(t, user, profile1)

	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 0)

	newName := "John Smith"
	newPassword := "1234password"

	// create join request with same email, new name and password
	id := addPendingJoin(t, newName, email1, newPassword, extra1)

	// activate pending join request and check token
	din1 := map[string]string{
		"id":       id,
		"email":    email1,
		"password": newPassword,
	}
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)

	session := getSession(t, user)

	var dout1 joinActivateOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	name2, email2, token2, extra2 := dout1.Name, dout1.Email, dout1.Token, dout1.Extra

	if name2 != newName || email2 != email1 || token2 != session || extra2 != extra1 {
		t.Fatalf("unexpected data. Got %s, %s, %s, %s. Want %s, %s, %s, %s.", name2, email2, token2, extra2, newName, email1, session, extra1)
	}

	// ensure profile was not reverted back to default
	assertProfileInData(t, dout1.Data, profile1)

	// ensure password is from join request
	_, _, hash := getUser(t, email1)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) != nil {
		t.Fatalf("unexpected password hash %s", hash)
	}
}

func TestJoinActivateFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingJoin(t, name, email, password, "")

	// unknown id
	din1 := map[string]string{
		"id":       "bf72f74b-6dbc-4d94-9b99-26413b3085e9",
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusNotFound)
	checkResponseBody(t, response, "")

	// incorrect email
	din2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// incorrect password
	din3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, din3)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 1)
}

func TestJoinActivateBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@b.com", "password": "password1234"}`, 400},                                                                 // no id
		{`{"id": 123, "email": "a@b.com", "password": "password1234"}`, 400},                                                      // invalid id
		{`{"id": "", "email": "a@b.com", "password": "password1234"}`, 400},                                                       // empty id
		{`{"id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "email": "a@b.com", "password": "password1234"}`, 400},                   // invalid id format
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "password": "password1234"}`, 400},                                       // no email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "", "password": "password1234"}`, 400},                          // empty email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": 123, "password": "password1234"}`, 400},                         // invalid email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "hi", "password": "password1234"}`, 400},                        // invalid email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@b.com"}`, 400},                                                // no password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@b.com", "password": 123}`, 400},                               // invalid password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": ""}`, 400},                               // empty password
		{fmt.Sprintf(`{"id": "%s", "email": "a@b.com", "password": "123"}`, longString(1)), 400},                                  // long invalid uuid
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "%s", "password": "123"}`, longEmail(1)), 400},      // too long email
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "%s"}`, longString(1)), 400}, // too long password
		// {`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "123"}`, 404},                            // data ok, not found
	}

	for _, din := range data {
		response := doPost(t, paths["joinActivate"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestJoinFlow(t *testing.T) {
	clearTables(t)

	// test with limit values
	name := longString(0)
	email := longEmail(0)
	password := longString(0)
	extra := longString(0)

	// create a pending join request
	din1 := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"extra":    extra,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 1)

	// pending join request id comes from email link
	// get directly from db
	id, _, _, _, _ := getPendingJoin(t, 0)

	// activate pending join
	din2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)

	var dout1 joinActivateOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if dout1.Name != name || dout1.Email != email || dout1.Extra != extra {
		t.Fatalf("invalid data. Got %s, %s, %s. Want %s, %s, %s.", dout1.Name, dout1.Email, dout1.Extra, name, email, extra)
	}
	assertUserData(t, dout1.Data, defaultUserData())

	// test join activate session token is valid
	response = doPatch(t, paths["auth_session"], nil, dout1.Token)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")

	// check signin works with email and password
	din3 := map[string]string{
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, din3)), "")
	checkResponseCode(t, response, http.StatusOK)

	// check signin data
	var dout2 signinOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if dout2.Name != name || dout2.Email != email {
		t.Fatalf("invalid data. Got %s, %s. Want %s, %s.", dout2.Name, dout2.Email, name, email)
	}

	// ensure join activate data and signin data match
	assertUserData(t, dout2.Data, dout1.Data)

	// check signin session token works
	response = doPatch(t, paths["auth_session"], nil, dout2.Token)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")
}

// ******************************************************************
func TestSignin(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	user := addUser(t, name1, email1, password1)

	din1 := map[string]string{
		"email":    email1,
		"password": password1,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertSessionCount(t, 1)

	session := getSession(t, user)

	var dout1 signinOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	name2, email2, token2 := dout1.Name, dout1.Email, dout1.Token
	if name2 != name1 || email2 != email1 || token2 != session {
		t.Fatalf("unexpected data: Got %s, %s, %s. Want %s, %s, %s", name2, email2, token2, name1, email1, session)
	}
	assertUserData(t, dout1.Data, defaultUserData())
}

func TestSigninData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now().Add(1*time.Millisecond))
	addUserTag(t, user, tag2, time.Now().Add(2*time.Millisecond))

	din1 := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	var dout1 signinOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall signinOut data: %s", err)
	}

	assertUserData(t, dout1.Data, newUserDataWithTags(profile, []string{tag1, tag2}))
}

func TestSigninFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// invalid email
	din1 := map[string]string{
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// invalid password
	din2 := map[string]string{
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")
}

func TestSigninBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                           // no data
		{`{"password": "password1234"}`, 400}, // no email
		{`{"email": 123, "password": "password1234"}`, 400},                         // unexpected email
		{`{"email": "", "password": "password1234"}`, 400},                          // empty email
		{`{"email": "foo@bar", "password": "password1234"}`, 400},                   // invalid email
		{`{"email": "foo@bar.com"}`, 400},                                           // no password
		{`{"email": "foo@bar.com", "password": 123}`, 400},                          // unexpected password
		{`{"email": "foo@bar.com", "password": ""}`, 400},                           // empty password
		{fmt.Sprintf(`{"email": "%s", "password": "123"}`, longEmail(1)), 400},      // too long email
		{fmt.Sprintf(`{"email": "a@b.com", "password": "%s"}`, longString(1)), 400}, // too long password
		// {`{"email": "foo@bar.com", "password": "password1234"}`, 401}, // data ok, unauthorized
	}

	for _, din := range data {
		response := doPost(t, paths["signin"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestResetPassword(t *testing.T) {
	clearTables(t)
	resetEmailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	lang := "en"
	extra := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"

	addUser(t, name, email, password)

	data := []map[string]string{
		{
			"email": email,
			"lang":  lang,
		},
		{
			"email": email,
			"lang":  lang,
			"extra": extra,
		},
	}

	for i, din := range data {
		email1, lang1, extra1 := din["email"], din["lang"], din["extra"]

		response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusCreated)

		id2, email2, extra2 := getPendingResetPassword(t, i)
		if email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected data. Got %s, %s. Want %s, %s", email2, extra2, email1, extra1)
		}
		assertMailer(t, resetEmailer(), id2, email1, lang1)
	}
}

func TestResetPasswordFails(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"

	din1 := map[string]string{
		"email": email,
		"lang":  "en",
	}

	// no user
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusNotFound)

	assertPendingResetPasswordCount(t, 0)
}

func TestResetPasswordBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},               // no email
		{`{"foo": 123}`, 400},     // no email
		{`{"email": 123}`, 400},   // invalid email
		{`{"email": ""}`, 400},    // empty email
		{`{"email": "a@b"}`, 400}, // incorrect email
		{`{"email": "a@foo.com", "lang": 123}`, 400},                             // invalid lang
		{fmt.Sprintf(`{"email": "%s", "lang": "en"}`, longEmail(1)), 400},        // too long email
		{fmt.Sprintf(`{"email": "a@b.com", "lang": "%s"}`, longString(1)), 400},  // too long lang
		{fmt.Sprintf(`{"email": "a@b.com", "extra": "%s"}`, longString(1)), 400}, // too long extra
		// {`{"email": "a@foo.com", "lang": "en"}`, 404}, // ok, not found
	}

	for _, din := range data {
		response := doPost(t, paths["resetPassword"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestNewPassword(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"

	newPassword1 := "password1111"
	newPassword2 := "password2222"

	user := addUser(t, name, email, password)

	data := []map[string]string{
		{
			"email":    email,
			"password": newPassword1,
		},
		{
			"email":    email,
			"password": newPassword2,
			"extra":    extra,
		},
	}

	for _, din := range data {
		email1, password1, extra1 := din["email"], din["password"], din["extra"]

		id := addPendingResetPassword(t, email1, extra1)
		din["id"] = id

		response := doPost(t, paths["newPassword"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusOK)

		assertPendingResetPasswordCount(t, 0)

		var dout newPasswordOut
		err := json.Unmarshal(response.Body.Bytes(), &dout)
		if err != nil {
			t.Fatalf("failed to unmarshall data: %s", err)
		}

		name2, email2, extra2 := dout.Name, dout.Email, dout.Extra

		if name2 != name || email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected data. Got %s, %s, %s. Want %s, %s, %s", name2, email2, extra2, name, email1, extra1)
		}

		// check password has changed
		_, _, hash2 := getUserByID(t, user)
		err = bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1))
		if err != nil {
			t.Fatalf("password not changed")
		}
	}
}
func TestNewPasswordData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	profile := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now().Add(1*time.Millisecond))
	addUserTag(t, user, tag2, time.Now().Add(2*time.Millisecond))

	id := addPendingResetPassword(t, email, "")

	din1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingResetPasswordCount(t, 0)

	var dout1 newPasswordOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall newPasswordOut data: %s", err)
	}

	assertUserData(t, dout1.Data, newUserDataWithTags(profile, []string{tag1, tag2}))
}

func TestNewPasswordFails(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingResetPassword(t, email, "")

	// unknown id
	din1 := map[string]string{
		"id":       "bf72f74b-6dbc-4d94-9b99-26413b3085e9",
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusNotFound)
	checkResponseBody(t, response, "")

	// incorrect email
	din2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// user gone (no user)
	din3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, din3)), "")
	checkResponseCode(t, response, http.StatusGone)
	checkResponseBody(t, response, "")

	assertPendingResetPasswordCount(t, 1)
}

func TestNewPasswordBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@foo.com", "password": "password1234"}`, 400},                                                                   // no id
		{`{"id": 123, "email": "a@foo.com", "password": "password1234"}`, 400},                                                        // invalid id
		{`{"id": "", "email": "a@foo.com", "password": "password1234"}`, 400},                                                         // empty id
		{`{id": "", "password": "password1234"}`, 400},                                                                                // no email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": 123, "password": "password1234"}`, 400},                              // invalid email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "", "password": "password1234"}`, 400},                               // empty email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "invalid", "password": "password1234"}`, 400},                        // incorrect email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@foo.com", }`, 400},                                                // no password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": 123}`, 400},                                // invalid password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": ""}`, 400},                                 // empty password
		{fmt.Sprintf(`{"id": "%s", "email": "a@foo.com", "password": "password1234"}`, longString(1)), 400},                           // invalid long uuid
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "%s", "password": "password1234"}`, longEmail(1)), 400}, // too long email
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "%s"}`, longString(1)), 400},     // too long password
		// {`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": "password1234"}`, 404}, // ok, not found
	}

	for _, din := range data {
		response := doPost(t, paths["newPassword"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestResetPasswordFlow(t *testing.T) {
	clearTables(t)
	resetEmailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	lang := "en"
	extra := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"

	profile := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	// request password reset
	din1 := map[string]string{"email": email, "lang": lang, "extra": extra}
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusCreated)

	id, email, extra := getPendingResetPassword(t, 0)
	assertMailer(t, resetEmailer(), id, email, lang)

	// verify password reset
	din2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusOK)

	var dout1 newPasswordOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if dout1.Extra != extra {
		t.Fatalf("unexpected extra in data. Got %s. Want %s", dout1.Extra, extra)
	}
	assertUserData(t, dout1.Data, newUserData(profile))

	// signin with new password
	din3 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, din3)), "")
	checkResponseCode(t, response, http.StatusOK)

	var dout2 signinOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
}

// ******************************************************************
func TestRenewSession(t *testing.T) {
	clearTables(t)

	old := getSessionTime(t, -2)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session1 := addSession(t, user)
	session2 := addSession(t, user)
	assertSessionCount(t, 2)

	renewSession(t, session1, old)
	renewSession(t, session2, old)

	response := doPatch(t, paths["auth_session"], nil, session1)
	checkResponseCode(t, response, http.StatusOK)

	app.cleanupDB()
	assertSessionCount(t, 1)

	if getSession(t, user) != session1 {
		t.Fatalf("unexpected session")
	}
	response = doPatch(t, paths["auth_session"], nil, session1)
	checkResponseCode(t, response, http.StatusOK)

	response = doPatch(t, paths["auth_session"], nil, session2)
	checkResponseCode(t, response, http.StatusUnauthorized)
}

func TestRenewSessionFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doPatch(t, paths["auth_session"], nil, "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// badly formed session
	response = doPatch(t, paths["auth_session"], nil, "hello")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// badly formed session
	response = doPatch(t, paths["auth_session"], nil, "123")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// unexpected session
	response = doPatch(t, paths["auth_session"], nil, "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestDeleteSession(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)
	assertSessionCount(t, 1)

	response := doDelete(t, paths["auth_session"], session)
	checkResponseCode(t, response, http.StatusNoContent)

	assertSessionCount(t, 0)
}

func TestDeleteSessionFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doDelete(t, paths["auth_session"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doDelete(t, paths["auth_session"], "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdatePassword(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	response := doPost(t, paths["auth_password"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")

	// check password has changed
	_, _, passwordHash := getUserByID(t, user)

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("unexpected password")
	}
}

func TestUpdatePasswordFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	// no session
	response := doPost(t, paths["auth_password"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_password"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid password
	din2 := map[string]string{
		"password":    newPassword,
		"newPassword": newPassword,
	}
	response = doPost(t, paths["auth_password"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusConflict)
}

func TestUpdatePasswordBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                              // no data
		{`{"foo": 123}`, 400},                    // no data
		{`{"newPassword": "1234password"}`, 400}, // no password
		{`{"password": 123, "newPassword": "1234password"}`, 400},                              // invalid password
		{`{"password": "", "newPassword": "1234password"}`, 400},                               // invalid password
		{`{"password": "password1234"}`, 400},                                                  // no new password
		{`{"password": "password1234", "newPassword": 123}`, 400},                              // invalid new password
		{`{"password": "password1234", "newPassword": ""}`, 400},                               // invalid new password
		{fmt.Sprintf(`{"password": "%s", "newPassword": "1234password"}`, longString(1)), 400}, // too long password
		{fmt.Sprintf(`{"password": "password1234", "newPassword": "%s"}`, longString(1)), 400}, // too long new password
	}

	for _, din := range data {
		response := doPost(t, paths["auth_password"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	response := doGet(t, paths["auth_account"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 accountOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if dout1.Name != name {
		t.Fatalf("unexpected name in data. Got %s. Want %s.", dout1.Name, name)
	}
}

func TestGetAccountFails(t *testing.T) {
	clearTables(t)

	// unauthorized
	response := doGet(t, paths["auth_account"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_account"], "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdateAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	newName := "John Döede"

	// modify name
	din1 := map[string]string{
		"name": newName,
	}
	response := doPut(t, paths["auth_account"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)

	currentName, _, _ := getUserByID(t, user)
	if currentName != newName {
		t.Fatalf("unexpected name. Got %s. Want %s", currentName, newName)
	}
}

func TestUpdateAccountFails(t *testing.T) {
	clearTables(t)

	din1 := map[string]string{
		"name": "John Doede",
	}
	// no session
	response := doPut(t, paths["auth_account"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPut(t, paths["auth_account"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

func TestUpdateAccountBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},            // no data
		{`{"foo": 123}`, 400},  // no data
		{`{"name": 123}`, 400}, // invalid name
		{`{"name": ""}`, 400},  // empty name
		{fmt.Sprintf(`{"name": "%s"}`, longString(1)), 400}, // empty name
	}

	for _, din := range data {
		response := doPut(t, paths["auth_account"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestRemoveAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]string{
		"email":    email,
		"password": password,
	}

	response := doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusNoContent)

	assertUserCount(t, 0)
	assertProfileCount(t, 0)
	assertSessionCount(t, 0)
}

func TestRemoveAccountFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// Test no session
	din1 := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// Test no password
	din2 := map[string]string{
		"email": email,
	}
	response = doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// Test incorrect email
	din3 := map[string]string{
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din3)), session)
	checkResponseCode(t, response, http.StatusConflict)

	// Test incorrect password
	din4 := map[string]string{
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, paths["auth_account_remove"], []byte(marshallAny(t, din4)), session)
	checkResponseCode(t, response, http.StatusConflict)

	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)
}

func TestRemoveAccountBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": 123, "password": "password1234"}`, 400},                                    // invalid email
		{`{"email": "", "password": "password1234"}`, 400},                                     // empty email
		{`{"email": "johndoe@example.com" "password": 1234}`, 400},                             // invalid password
		{`{"email": "johndoe@example.com" "password": ""}`, 400},                               // empty password
		{fmt.Sprintf(`{"email": "%s" "password": "123"}`, longEmail(1)), 400},                  // too long email
		{fmt.Sprintf(`{"email": "johndoe@example.com" "password": "%s"}`, longString(1)), 400}, // too long password
	}

	for _, din := range data {
		response := doPost(t, paths["auth_account_remove"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)
	session := addSession(t, user)

	response := doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertUserData(t, dout1, newUserData(profile))
}

func TestGetDataFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doGet(t, paths["auth_data"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_data"], "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdateProfile(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// get user data for valid profile timestamp
	response := doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}

	assertUserData(t, dout1, defaultUserData())

	// update profile
	din1 := map[string]any{
		"data":      profile.Data,
		"timestamp": dout1.Profile.Timestamp,
	}
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)

	err = json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertUserData(t, dout1, newUserData(profile))
}

func TestUpdateProfileFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"darkmode": 1,
		},
	}

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]any{
		"data":      profile.Data,
		"timestamp": time.Now().AddDate(0, 0, -1),
	}
	// no session
	response := doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid timestamp
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusConflict)
}

func TestUpdateProfileBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"data": "", "timestamp": "2006-01-02T15:04:05Z07:00"}`, 400},                                         // invalid profile
		{`{"data": 123, "timestamp": "2006-01-02T15:04:05Z07:00"}`, 400},                                        // invalid profile
		{`{"data": {}, "timestamp": 123}`, 400},                                                                 // invalid timestamp
		{`{"data": {}, "timestamp": ""}`, 400},                                                                  // invalid timestamp
		{`{"data": {}, "timestamp": "2006-01-02T15:04"}`, 400},                                                  // invalid timestamp
		{fmt.Sprintf(`{"data": {"data": "%s"}, "timestamp": "2006-01-02T15:04:05Z07:00"}`, longString(1)), 400}, // too long profile data
		{fmt.Sprintf(`{"data": {}, "timestamp": "%s"}`, longString(1)), 400},                                    // too long timestamp
	}

	for _, din := range data {
		response := doPost(t, paths["auth_data_profile"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestAddTags(t *testing.T) {
	clearTables(t)

	start := time.Now()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	// connect one tag
	din1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{tag1})
	for _, tag := range dout1.Tags {
		assertTimestamp(t, tag.Added, start, time.Now())
		if tag.Accessed != "" || tag.ActedOn != "" {
			t.Fatalf("accessed and acted_on timestamps not empty strings")
		}
	}

	// connect two additional tags
	din2 := map[string]any{
		"tags": []string{tag2, tag3},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 3)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertUserDataTags(t, dout2, []string{tag1, tag2, tag3})
	assertTagsEqual(t, dout1.Tags[0], dout2.Tags[0])
}

func TestAddTagsTwice(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	din1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{tag1})

	// connect tag1 again with two additional tags
	din2 := map[string]any{
		"tags": []string{tag1, tag2, tag3},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 3)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout2, []string{tag1, tag2, tag3})
	assertTagsEqual(t, dout1.Tags[0], dout2.Tags[0])
}

func TestAddTagsFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	din1 := map[string]any{
		"tags": []string{tag1},
	}
	// no session
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	din2 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusNotFound)
	assertUserTagCount(t, user, 0)

	// valid and invalid tag ids mixed
	din3 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9", tag2},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din3)), session)
	checkResponseCode(t, response, http.StatusNotFound)
	assertUserTagCount(t, user, 0)
}

func TestAddTagsBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                  // no data
		{`{"foo": 123}`, 400},        // no data
		{`{"tags": "hello"`, 400},    // invalid tags
		{`{"tags": 123`, 400},        // invalid tags
		{`{"tags": []`, 400},         // empty tags
		{`{"tags": ["hello"]}`, 400}, // invalid tag id
		{`{"tags": ["bf72f74b-6dbc-4d94-9b99-26413b3085e9", "hello"]`, 400}, // invalid tag id
	}

	for _, din := range data {
		response := doPost(t, paths["auth_data_tags"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestRemoveTags(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())

	// disconnect tag
	din1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{})
	assertUserTagCount(t, user, 0)
}

func TestRemoveTagsMultiple(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())
	addUserTag(t, user, tag3, time.Now())

	// disconnect tag
	din1 := map[string]any{
		"tags": []string{tag1, tag3},
	}
	response := doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{tag2})
}

func TestRemoveTagsIgnored(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())

	// invalid tag id
	din1 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response := doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 2)

	// valid and invalid tag ids mixed
	din2 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	// already removed
	din3 := map[string]any{
		"tags": []string{tag1},
	}
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din3)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)
}

func TestRemoveTagsFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())

	din1 := map[string]any{
		"tags": []string{tag1},
	}
	// no session
	response := doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	din2 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 2)

	// valid and invalid tag ids mixed
	din3 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9", tag2},
	}
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din3)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 0)

	// already removed
	din4 := map[string]any{
		"tags": []string{tag1},
	}
	response = doPost(t, paths["auth_data_tags_remove"], []byte(marshallAny(t, din4)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 0)
}

func TestRemoveTagsBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                  // no data
		{`{"foo": 123}`, 400},        // no data
		{`{"tags": "hello"`, 400},    // invalid tags
		{`{"tags": 123`, 400},        // invalid tags
		{`{"tags": []`, 400},         // empty tags
		{`{"tags": ["hello"]}`, 400}, // invalid tag id
		{`{"tags": ["bf72f74b-6dbc-4d94-9b99-26413b3085e9", "hello"]`, 400}, // invalid tag id
	}

	for _, din := range data {
		response := doPost(t, paths["auth_data_tags_remove"], []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetTag(t *testing.T) {
	clearTables(t)

	start := time.Now()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)
	assertTagCount(t, 1)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOutGet
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1.Tag, tagOut{tag, tname, tcategory, tdata, ""})
	assertTimestamp(t, dout1.Accessed, start, time.Now())
}

func TestGetTagUpdatesTimestamps(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOutGet
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	time.Sleep(2 * time.Millisecond)
	start := time.Now()

	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout2 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTimestamp(t, dout2.Accessed, start, time.Now())

	if dout2.Tag.ModifiedAt != dout1.Tag.ModifiedAt {
		t.Fatalf("modified_at changed unexpectedly")
	}
	if dout2.Accessed <= dout1.Accessed {
		t.Fatalf("unexpected timestamp, %s <= than %s", dout2.Accessed, dout1.Accessed)
	}
}

func TestGetTagFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)

	// invalid session
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doGet(t, p, "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusNotFound)

	// invalid tag id for go-playground validator uuid4?
	p = pathWithParam(paths["auth_tags"], ":id", "11111111-1111-1111-1111-111111111111")
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusNotFound)
}

func TestGetTagBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// bad tag id
	p := pathWithParam(paths["auth_tags"], ":id", "hello")
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// bad tag id
	p = pathWithParam(paths["auth_tags"], ":id", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusBadRequest)
}

// ******************************************************************
func TestUpdateTag(t *testing.T) {
	clearTables(t)

	start := time.Now()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]any{
		"value": 2,
	}

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, tagDataIn{din1})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOutPost
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1.Tag, tagOut{tag, tname, tcategory, din1, ""})
	assertTimestamp(t, dout1.Tag.ModifiedAt, start, time.Now())
	assertTimestamp(t, dout1.ActedOn, start, time.Now())
}

func TestUpdateTagUpdatesTimestamps(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]any{
		"value": 2,
	}

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, tagDataIn{din1})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOutPost
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	time.Sleep(2 * time.Millisecond)
	start := time.Now()

	din2 := map[string]any{
		"value": 3,
	}

	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din2})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout2 tagOutPost
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTimestamp(t, dout2.ActedOn, start, time.Now())

	if dout2.Tag.ModifiedAt <= dout1.Tag.ModifiedAt {
		t.Fatalf("modified_at did not change")
	}
	if dout2.ActedOn <= dout1.ActedOn {
		t.Fatalf("unexpected timestamp, %s <= %s", dout2.ActedOn, dout1.ActedOn)
	}
}

func TestUpdateTagFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	din1 := map[string]any{
		"value": 42,
	}
	tag := addTag(t, tname, tcategory, din1)

	// invalid session
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, tagDataIn{din1})), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag
	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din1})), session)
	checkResponseCode(t, response, http.StatusNotFound)
}

func TestUpdateTagBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	din1 := map[string]any{
		"value": 42,
	}

	// bad tag id
	p := pathWithParam(paths["auth_tags"], ":id", "hello")
	response := doPost(t, p, []byte(marshallAny(t, tagDataIn{din1})), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// bad tag id
	p = pathWithParam(paths["auth_tags"], ":id", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	response = doPost(t, p, []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                // no data
		{`{"foo": 123}`, 400},      // no data
		{`{"data":}`, 400},         // no data
		{`{"data": 123}`, 400},     // invalid data
		{`{"data": "hello"}`, 400}, // invalid data
		// {`{"data": "hello"}`, 400}, // invalid data
	}

	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	for _, din := range data {
		response := doPost(t, p, []byte(din.data), session)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

func TestUpdateTagTooMuchData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag := addTag(t, "tag1", "nop", map[string]any{})

	// too much data
	din1 := tagDataIn{map[string]any{
		"data": longString(maxBodySize),
	}}
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusBadRequest)
}

// ******************************************************************
func TestTagAccessed(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user1 := addUser(t, name, email, password)
	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	session1 := addSession(t, user1)
	session2 := addSession(t, user2)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	din1 := map[string]any{
		"tags": []string{tag1, tag2},
	}
	// connect tags to user1
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user1, 2)
	assertUserTagCount(t, user2, 0)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{tag1, tag2})
	assertTagsAdded(t, dout1.Tags)

	// connect tags to user2
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session2)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user2, 2)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout2, []string{tag1, tag2})
	assertTagsAdded(t, dout2.Tags)

	// user1 accesses tag1
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check accessed
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var dout3 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout3)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagAccessed(t, dout3.Tags[0])
	assertTagAddedOnly(t, dout3.Tags[1])

	time.Sleep(2 * time.Millisecond)

	// user1 accesses tag1 and tag2
	p = pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	p = pathWithParam(paths["auth_tags"], ":id", tag2)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check accessed
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var dout4 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout4)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagAccessed(t, dout4.Tags[0])
	assertTagAccessed(t, dout4.Tags[1])
	if dout4.Tags[0].Accessed == dout3.Tags[0].Accessed {
		t.Fatalf("tag1 accessed did not change %v", dout4.Tags[0].Accessed)
	}

	// get user 2 data and check all still added
	response = doGet(t, paths["auth_data"], session2)
	checkResponseCode(t, response, http.StatusOK)

	var dout5 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout5)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagsAdded(t, dout5.Tags)
}

func TestTagActedOn(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user1 := addUser(t, name, email, password)
	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	session1 := addSession(t, user1)
	session2 := addSession(t, user2)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	din1 := map[string]any{
		"tags": []string{tag1, tag2},
	}
	// connect tags to user1
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user1, 2)
	assertUserTagCount(t, user2, 0)

	var dout1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout1, []string{tag1, tag2})
	assertTagsAdded(t, dout1.Tags)

	// connect tags to user2
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din1)), session2)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user2, 2)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout2, []string{tag1, tag2})
	assertTagsAdded(t, dout2.Tags)

	// user 1 acts on tag 1
	d2 := tagDataIn{map[string]any{
		"value": 42,
	}}
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check acted on
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var dout3 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout3)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagActedOn(t, dout3.Tags[0])
	assertTagAddedOnly(t, dout3.Tags[1])

	time.Sleep(1 * time.Millisecond) // ensure time tags change

	// user1 acts on tag1 and tag2
	p = pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	p = pathWithParam(paths["auth_tags"], ":id", tag2)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check acted on
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var dout4 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout4)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagActedOn(t, dout4.Tags[0])
	assertTagActedOn(t, dout4.Tags[1])
	if dout4.Tags[0].ActedOn == dout3.Tags[0].ActedOn {
		t.Fatalf("tag1 accessed did not change")
	}

	// get user 2 data and check all still added
	response = doGet(t, paths["auth_data"], session2)
	checkResponseCode(t, response, http.StatusOK)

	var dout5 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout5)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagsAdded(t, dout5.Tags)
}
