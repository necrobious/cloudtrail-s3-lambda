cloudtrail-s3-lambda
====================
**NOTE: This in a work-in-progress, it works for my needs, but YMMV, I do not advise deploying this into a produciton AWS account, unless you know what you are doing.**

A simple POC of a rust lambda for searching CloudTrail logs and publishing matches to an SNS topic.
inspired by: https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail-example.html

The lambda is intended to be configured as an S3 Notification Event on a bucket configured in CloudTrail.
When CloudTrail writes an object to the configured bucket, the lambda:
 - receives an S3Event as its input. 
 - extracts the bucket and key values from the input event.
 - retreives & gunzips the cloudtrail log from S3.
 - runs the contents of the log through one or more alarms, looking for matches.
 - publishes any matches found to the configured SNS topic.


Building
========
There are a couple of hurtles to getting this project working, that will upefully improve wth time. 
 - `lambda_runtime` recommends building the Rust lambda with `x86_64-unknown-linux-musl` compilation target, and on Amazon Linux. 
 - we use the Rusoto project access S3 and SNS, both over HTTPS, which at the moment, only OpenSSL will work against `musl-libc`
 - Amazon Linux OpenSSL version does not support `musl` out of the box, meaning we'll need to build OpenSSL from source (_vomit_). 

Overview
--------
For now, we are using a docker container running Amazon Linux that builds the rust toolchain using rustup, 
the musl toolchain & and OpenSSL library from source (verified using `gpg.keys`),
and then echos `fn main() {}` in to `src/main.rs` and `cargo build`s the project. 
By doing a dummy build ahead of copying the project sources into the container, we will be able to utilize the docker cache of the project's
dependencies dring development. Finally the project sources are copied into the container and built using `cargo`. 

After the `bootstrap` binary is built, it then needs to be assembled into a zip file, per AWS' instrustions, 
then the resulting `aws_lambda.zip` file needs to be copiied out of the container, and placed into the project's directory. 

All of this work is done between the contents of `Dockerfile` and the `scripts/build.sh` script. 
`scripts/build.sh` relies on a dot file in the project root named `.env`.
`scripts/build.sh` will source the contents of `.env` prior to invoking the aws cli 

An example of `.env` is:
```
# IAM Role that has permission to read CloudTrail logs in S3 and Publish to the $ALERTS_TOPIC_ARN SNS topic.
ROLE_ARN=arn:aws:iam::<account-id>:role/Lambda-CloudTrail-S3

# SNS topic to publish alerts to
ALERTS_TOPIC_ARN=arn:aws:sns:us-west-2:<account-id>:cloudtrail-alarms

# live cloudtrail to test matches against.
INTEGRATION_TEST_S3_BUCKET=<s3-cloudtrail-bucket>
INTEGRATION_TEST_S3_KEY=AWSLogs/<account-id>/CloudTrail/us-west-2/2018/12/28/<account-id>_CloudTrail_us-west-2_20192128T2210Z_ZXn3PxvTbIZ5qEuP.json.gz
```

NOTE: the filename `.env` has been added to the contents of `.gitignore` to prevent you accidentially committing sensitive account information into your source control. 




Deploying
=========

The Lambda's execution role was configured with the following three policies.

Policy granting permission to get objects from the CloudTrail S3 Bucket, and to Publish to our SNS topic, when matches are found.
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "sns:Publish"
            ],
            "Resource": [
                "arn:aws:sns:us-west-2:<account-id>:cloudtrail-alerts",
                "arn:aws:s3:::<s3-cloudtrail-bucket>/AWSLogs/*"
            ]
        }
    ]
}
```

Policy granting permission to create CloudWatch Logs 
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

Policy granting permission to create XRay traces
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "xray:PutTraceSegments",
            "Resource": "*"
        }
    ]
}
```


The initial deployment can be done using the `scripts/create.sh` script, creates the lambda using the aws cli; it relies on a dot file in the project root named `.env` as well a typical AWS CLI credentials being available at `~/.aws/credentials`.
After the inital creation, `scripts/update.sh` can be used to update the function, testing the function can b done with `scripts/test-deploy.sh`.


