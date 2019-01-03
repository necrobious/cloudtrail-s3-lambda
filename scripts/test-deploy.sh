#!/bin/bash

if [[ ! -f ./.env ]];
then
    (>&2 echo "No .env file found in project, exiting!")
    exit 1
fi

source ./.env

if [ -z "$INTEGRATION_TEST_S3_BUCKET" ]; then
    echo "Need to set INTEGRATION_TEST_S3_BUCKET in your .env file"
    exit 1
fi


if [ -z "$INTEGRATION_TEST_S3_KEY" ]; then
    echo "Need to set INTEGRATION_TEST_S3_KEY in your .env file"
    exit 1
fi


aws lambda invoke --function-name cloudtrail-s3-lambda \
--payload '{"Records":[{"eventVersion":"2.0","eventSource":"aws:s3","awsRegion":"us-east-1","eventTime":"1970-01-01T00:00:00.123Z","eventName":"ObjectCreated:Put","userIdentity":{"principalId":"EXAMPLE"},"requestParameters":{"sourceIPAddress":"127.0.0.1"},"responseElements":{"x-amz-request-id":"C3D13FE58DE4C810","x-amz-id-2":"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD"},"s3":{"s3SchemaVersion":"1.0","configurationId":"testConfigRule","bucket":{"name":"'${INTEGRATION_TEST_S3_BUCKET}'","ownerIdentity":{"principalId":"EXAMPLE"},"arn":"arn:aws:s3:::mybucket"},"object":{"key":"'${INTEGRATION_TEST_S3_KEY}'","size":1024,"urlDecodedKey":"HappyFace.jpg","versionId":"version","eTag":"d41d8cd98f00b204e9800998ecf8427e","sequencer":"Happy Sequencer"}}}]}' \
./test-output.json

