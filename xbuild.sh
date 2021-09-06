#!/bin/sh

docker build -t spotty-cross - < docker/Dockerfile
docker run --rm -v $PWD/target:/build -v $PWD:/src spotty-cross