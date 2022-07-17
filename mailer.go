package main

import "fmt"

type mailer func(email, url, lang string) error

func sasMailer(email, url, lang string) error {
	fmt.Printf("********** sas mailer: %s %s %s\n", email, url, lang)
	return nil
}
