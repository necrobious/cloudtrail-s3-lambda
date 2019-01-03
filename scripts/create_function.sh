#!/bin/bash

# There should be a .env file which contains a variable called ROLE_ARN

ZIP_FILE="./aws_lambda.zip";

if [[ ! -f ./.env ]];
then
    (>&2 echo "No .env file found in project, exiting!")
    exit 1
fi

if [[ ! -f ${ZIP_FILE} ]];
then
    (>&2 echo "No zip file names ${ZIP_FILE} could be found")
    exit 1
fi

source ./.env

aws lambda create-function --function-name cloudtrail-s3-lambda \
--handler ignored \
--zip-file fileb://${ZIP_FILE} \
--runtime provided \
--role ${ROLE_ARN} \
--environment '{"Variables":{"RUST_BACKTRACE":"1","RUST_LOG":"bootstrap=debug","ALERTS_TOPIC_ARN":"'${ALERTS_TOPIC_ARN}'"}}' \
--tracing-config Mode=Active
