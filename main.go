package main

import (
	"log"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
)

const (
	configDelimeter = "."
	configName      = "env.json"
	configPrefix    = ""
)

func main() {
	k := koanf.New(configDelimeter)

	if err := k.Load(file.Provider(configName), json.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	k.Load(env.Provider(configPrefix, configDelimeter, nil), nil)

	var app GoTags

	app.initialize(k.String("GOTAGS_DATABASE_URL"))
	defer app.pool.Close()

	app.run(k.String("GOTAGS_SERVER"))
}
