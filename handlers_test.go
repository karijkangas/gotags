package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// ******************************************************************
func TestNopHandler(t *testing.T) {
	clearTables(t)

	user := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	session := addSession(t, user)
	adminSession := addAdminSession(t, user)

	// admin adds nop category tag with default data
	start := time.Now()
	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	defaultData := map[string]any{}

	din1 := map[string]string{
		"name":     tagName1,
		"category": tagCategory1,
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), adminSession)
	checkResponseCode(t, response, http.StatusCreated)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	tag1 := dout1.ID
	assertTimestamp(t, dout1.ModifiedAt, start, time.Now())

	// user adds tag to user data
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	din2 := map[string]any{
		"tags": []string{tag1},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout2, []string{tag1})
	assertTimestamp(t, dout2.Tags[0].Added, start, time.Now())
	assertTagAddedOnly(t, dout2.Tags...)

	// user gets tag data, ensure it matches expected default
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout3 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout3)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout3.Tag, tagOut{tag1, tagName1, tagCategory1, defaultData, dout1.ModifiedAt})
	assertTimestamp(t, dout3.Accessed, start, time.Now())

	// user updates tag data
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	din3 := map[string]any{
		"value": 1,
	}
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din3})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout4 tagOutPost
	err = json.Unmarshal(response.Body.Bytes(), &dout4)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout4.Tag, tagOut{tag1, tagName1, tagCategory1, din3, ""})
	assertTimestamp(t, dout4.Tag.ModifiedAt, start, time.Now())
	assertTimestamp(t, dout4.ActedOn, start, time.Now())

	// get tag data, ensure it matches updated data
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout5 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout5)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout5.Tag, tagOut{tag1, tagName1, tagCategory1, din3, dout4.Tag.ModifiedAt})
	assertTimestamp(t, dout5.Accessed, start, time.Now())

	// get user data
	response = doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout6 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout6)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	if dout6.Tags[0].Added != dout2.Tags[0].Added {
		t.Fatalf("unexpected added in final tag data. Got %s. Want %s", dout6.Tags[0].Added, dout2.Tags[0].Added)
	}
	if dout6.Tags[0].Accessed != dout5.Accessed {
		t.Fatalf("unexpected accessed in final tag data. Got %s. Want %s", dout6.Tags[0].Accessed, dout5.Accessed)
	}
	if dout6.Tags[0].ActedOn != dout4.ActedOn {
		t.Fatalf("unexpected acted_on in final tag data. Got %s. Want %s", dout6.Tags[0].ActedOn, dout4.ActedOn)
	}
}

// ******************************************************************
func TestCounterHandler(t *testing.T) {
	clearTables(t)

	user := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	session := addSession(t, user)
	adminSession := addAdminSession(t, user)

	// admin adds counter category tag with default data
	start := time.Now()
	tagName1 := "Tag #1"
	tagCategory1 := "counter"
	defaultData := map[string]any{"counter": 0}

	din1 := map[string]string{
		"name":     tagName1,
		"category": tagCategory1,
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), adminSession)
	checkResponseCode(t, response, http.StatusCreated)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	tag1 := dout1.ID
	assertTimestamp(t, dout1.ModifiedAt, start, time.Now())

	// user adds tag to user data
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	din2 := map[string]any{
		"tags": []string{tag1},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din2)), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertUserDataTags(t, dout2, []string{tag1})
	assertTimestamp(t, dout2.Tags[0].Added, start, time.Now())
	assertTagAddedOnly(t, dout2.Tags...)

	// user gets tag data, ensure it matches expected default
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout3 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout3)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout3.Tag, tagOut{tag1, tagName1, tagCategory1, defaultData, dout1.ModifiedAt})
	assertTimestamp(t, dout3.Accessed, start, time.Now())

	// user increments counter
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	din3 := map[string]any{
		"operation": "increment",
	}
	data1 := map[string]any{
		"counter": 1,
	}
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din3})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout4 tagOutPost
	err = json.Unmarshal(response.Body.Bytes(), &dout4)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout4.Tag, tagOut{tag1, tagName1, tagCategory1, data1, ""})
	assertTimestamp(t, dout4.Tag.ModifiedAt, start, time.Now())
	assertTimestamp(t, dout4.ActedOn, start, time.Now())

	// user increments counter again
	time.Sleep(2 * time.Millisecond)
	start = time.Now()
	data2 := map[string]any{
		"counter": 2,
	}

	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din3})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout5 tagOutPost
	err = json.Unmarshal(response.Body.Bytes(), &dout5)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout5.Tag, tagOut{tag1, tagName1, tagCategory1, data2, ""})
	assertTimestamp(t, dout5.Tag.ModifiedAt, start, time.Now())
	assertTimestamp(t, dout5.ActedOn, start, time.Now())

	// get tag data, ensure it matches updated data
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout6 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout6)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout6.Tag, tagOut{tag1, tagName1, tagCategory1, data2, dout5.Tag.ModifiedAt})
	assertTimestamp(t, dout6.Accessed, start, time.Now())

	// get user data
	response = doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout7 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout7)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	if dout7.Tags[0].Added != dout2.Tags[0].Added {
		t.Fatalf("unexpected added in final tag data. Got %s. Want %s", dout7.Tags[0].Added, dout2.Tags[0].Added)
	}
	if dout7.Tags[0].Accessed != dout6.Accessed {
		t.Fatalf("unexpected accessed in final tag data. Got %s. Want %s", dout7.Tags[0].Accessed, dout6.Accessed)
	}
	if dout7.Tags[0].ActedOn != dout5.ActedOn {
		t.Fatalf("unexpected acted_on in final tag data. Got %s. Want %s", dout7.Tags[0].ActedOn, dout5.ActedOn)
	}
}

func TestCounterHandlerBadData(t *testing.T) {
	clearTables(t)

	user := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	session := addSession(t, user)
	adminSession := addAdminSession(t, user)

	// admin adds counter category tag with default data
	tagName1 := "Tag #1"
	tagCategory1 := "counter"
	defaultData := map[string]any{"counter": 0}

	din1 := map[string]string{
		"name":     tagName1,
		"category": tagCategory1,
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), adminSession)
	checkResponseCode(t, response, http.StatusCreated)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	tag1 := dout1.ID

	p := pathWithParam(paths["auth_tags"], ":id", tag1)

	// no operation
	din3 := map[string]any{}
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din3})), session)
	checkResponseCode(t, response, http.StatusForbidden)

	// invalid operation
	din4 := map[string]any{
		"operation": 10,
	}
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din4})), session)
	checkResponseCode(t, response, http.StatusForbidden)

	// unknown operation
	din5 := map[string]any{
		"operation": "hello",
	}
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din5})), session)
	checkResponseCode(t, response, http.StatusForbidden)

	// ensure tag data has not changed
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout2 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout2.Tag, tagOut{tag1, tagName1, tagCategory1, defaultData, ""})
}
