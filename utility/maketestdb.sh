#!/bin/bash

#sudo -u postgres psql -c 'create database gotags_test;'
psql -c 'drop database gotags_test;'
psql -c 'create database gotags_test;'
psql gotags_test -f utility/initdb.sql
