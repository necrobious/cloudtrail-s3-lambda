#!/bin/sh
NAME=cloudtrail-s3-lambda

docker build .
docker run --name ${NAME} $(docker images -q | head -1) /bin/true
docker cp ${NAME}:/artifacts/aws_lambda.zip .
docker rm ${NAME}
