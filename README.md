# gotags

gotagsavaruus.com

#

Code starts from [main.go](https://github.com/karijkangas/gotags/blob/main/main.go)

Action from [app.go](https://github.com/karijkangas/gotags/blob/main/app.go)

main_test.go tests main.go.

env.json
environment variables: database, server, domain

# Local Debian 11 development image

```shell

create debian 11 qemu vm image
	root/gotags
	gotags/gotags

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
sudo ansible-playbook --connection=local --inventory 127.0.0.1, /vm-share/gotags/utility/playbook-bullseye.yml


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
go test -run TestDeleteAccountInvalid

go build
./gotags
```

# Swagger UI (Apple)

```shell
docker buildx build --platform linux/arm64/v8 --tag swagger-ui:v1 --tag swagger-ui:latest .
docker run -p 8080:8080 -v /Users/gotags/vm-share-gotags/gotags/utility/api.yaml:/app/swagger.yaml -e SWAGGER_JSON=/app/swagger.yaml swagger-ui:v1
```
