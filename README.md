# gotags

gotagsavaruus.com

#

Development done in main, otherwise not yet done.

Code starts from [main.go](https://github.com/karijkangas/gotags/blob/main/main.go)

Action from [app.go](https://github.com/karijkangas/gotags/blob/main/app.go)

[main_test.go](https://github.com/karijkangas/gotags/blob/main/main_test.go) tests main.go

Create local [env.json](https://github.com/karijkangas/gotags/blob/main/env.json) with variables database, server, and domain, like so:

```json
{
  "GOTAGS_DATABASE_URL": "postgres://gotags:gotags@localhost:5432/gotags",
  "GOTAGS_SERVER": "0.0.0.0:8080",
  "GOTAGS_DOMAIN": "https://gotagsavaruus.com/"
}
```

Note these variables work inside virtual machine.

# Local Debian 11 development image

Create debian 11 (qemu) vm image:

- root/gotags
- gotags/gotags

```shell
apt-get install sudo vim cifs-utils ansible

usermod -aG sudo gotags
vim /etc/sudoers.d/gotags
	gotags     ALL=(ALL) NOPASSWD:ALL
chmod 0440 /etc/sudoers.d/gotags

shutdown -h now
./start-debian.sh

ssh-copy-id -p 8022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null gotags@localhost
ssh gotags@localhost -p 8022

sudo mkdir /vm-share

sudo vim /root/.smbcredentials
	username=gotags
	password=gotags

sudo chmod 400 /root/.smbcredentials

sudo groupadd -f gotags
sudo useradd -g gotags gotags

# ifconfig | grep inet

sudo mount -t cifs -o rw,vers=3.0,credentials=/root/.smbcredentials -o uid=gotags -o gid=gotags //192.168.1.114/vm-share-gotags /vm-share

sudo vim /etc/fstab
	//192.168.1.114/vm-share-gotags /vm-share cifs vers=3.0,credentials=/root/.smbcredentials,uid=gotags,gid=gotags

sudo mount -a

sudo ansible-galaxy install gantsign.golang
#sudo ansible-playbook --connection=local --inventory 127.0.0.1, /vm-share/gotags/utility/playbook-bullseye.yml
sudo ansible-playbook --connection=local --inventory 127.0.0.1, /vm-share/gotags/utility/playbook-bullseye-debug.yml


sudo su - gotags
psql gotags -f utility/initdb.sql


devchrome 2>&1 &
```

# Initialize database (Debian 11)

TODO.

```shell

psql # initialize
	CREATE ROLE gotags WITH PASSWORD 'gotags' WITH LOGIN;
	CREATE DATABASE gotags OWNER gotags;
	CREATE DATABASE gotags_test OWNER gotags;
	# something missing?

psql gotags_test -f utility/initdb.sql

psql # reset database
	\c gotags
	\i utility/initdb.sql  # TODO: DANGEROUS!!!

	\c gotags_test
	\i utility/initdb.sql  # TODO: DANGEROUS!!!
```

# Go development (Debian 11)

```shell
go test
go test -run TestDeleteAccount

go build
./gotags
```

Gotags debug API for automatic testing:

```shell
go test --tags=gotags_debug_api
go build --tags=gotags_debug_api
```

# Remote debug using Delve

```shell
go install github.com/go-delve/delve/cmd/dlv@latest
dlv --listen=:2345 --headless --api-version=2 --log test -- -test.run ^TestRenewSession$
```

VSC launch.json

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch remote dlv",
      "type": "go",
      "request": "attach",
      "mode": "remote",
      "remotePath": "/vm-share/gotags",
      "port": 8345,
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

# Swagger UI (Apple)

```shell
docker buildx build --platform linux/arm64/v8 --tag swagger-ui:v1 --tag swagger-ui:latest .
docker run -p 8080:8080 -v /Users/gotags/vm-share-gotags/gotags/utility/api.yaml:/app/swagger.yaml -e SWAGGER_JSON=/app/swagger.yaml swagger-ui:v1
```
