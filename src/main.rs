#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate lambda_runtime as lambda;

extern crate log;

extern crate aws_lambda_events;
extern crate jmespath;
extern crate libflate;
extern crate rusoto_core;
extern crate rusoto_sns;
extern crate simple_logger;

mod alarm;
mod alert;
mod errors;

use aws_lambda_events::event::s3::S3Event;
use serde_json::{self, Value};
use std::default::Default;
use std::env;

use rusoto_core::request::BufferedHttpResponse;
use rusoto_core::Region;
use rusoto_s3::{GetObjectError, GetObjectRequest, S3Client, S3};
use rusoto_sns::{PublishInput, Sns, SnsClient};

use crate::errors::CloudTrailError;
use lambda::error::HandlerError;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

fn s3_get_obj_req_from_s3_event(s3_event: S3Event) -> Vec<GetObjectRequest> {
    let recs = s3_event.records;
    recs.iter()
        .flat_map(|rec| match (&rec.s3.bucket.name, &rec.s3.object.key) {
            (Some(bucket), Some(key)) => vec![GetObjectRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                ..Default::default()
            }],
            _ => vec![],
        })
        .collect()
}

fn do_error<E>(e: E, ctx: &lambda::Context) -> Result<String, HandlerError>
where
    E: ToString,
{
    Err(ctx.new_error(e.to_string().as_str()))
}

fn fetch_finding(client: &S3Client, req: &GetObjectRequest) -> Result<Vec<Value>, CloudTrailError> {
    client
        .get_object(req.clone())
        .sync()
        .map_err(|e| match e {
            GetObjectError::Unknown(BufferedHttpResponse { status: s, .. })
                if s.as_u16() == 403 =>
            {
                CloudTrailError::new_s3get_object_auth_error(req.key.clone(), req.bucket.clone())
            }
            _ => CloudTrailError::GenericS3GetObjectError(e),
        })
        .and_then(|go| go.body.ok_or(CloudTrailError::MissingS3Body))
        .map(|body_stream| body_stream.into_blocking_read())
        .and_then(|blocking_reader| {
            serde_json::from_reader(blocking_reader)
                .map_err(|_e| CloudTrailError::S3BodyReaderError)
        })
        .and_then(|ref v| alarm::Alarms::detect(v))
}

fn fetch_findings(client: &S3Client, input: &Value) -> Result<Vec<Value>, CloudTrailError> {
    let s3_event =
        serde_json::from_value(input.clone()).map_err(|_e| CloudTrailError::InputJsonError)?;

    let events = s3_get_obj_req_from_s3_event(s3_event);

    let mut findings = Vec::new();
    for event in events {
        let finding = fetch_finding(client, &event)?;
        findings.extend(finding);
    }
    Ok(findings)
}

fn my_handler(input: Value, ctx: lambda::Context) -> Result<String, HandlerError> {
    //let alert_topic_arn  = env::var("ALERTS_TOPIC_ARN").map_err(|e| ctx.new_error(e.to_string().as_str()))?;
    let alert_topic_arn = env::var("ALERTS_TOPIC_ARN");
    if alert_topic_arn.is_err() {
        return do_error("Expected ALERTS_TOPIC_ARN to be set in env", &ctx);
    }

    let sns_client = SnsClient::new(Region::UsWest2);
    let s3_client = S3Client::new(Region::UsWest2);

    let findings =
        fetch_findings(&s3_client, &input).map_err(|e| e.convert_to_cloudtrail_error(&ctx))?;

    let len = findings.len();

    if len > 0 {
        let msg_json = Value::Array(findings);
        let msg = serde_json::to_string(&msg_json)
            .map_err(|_e| ctx.new_error("Unable to serialize findings into a JSON string"))?;

        let request = PublishInput {
            message: msg,
            topic_arn: Some(alert_topic_arn.unwrap()),
            ..Default::default()
        };

        let _publish_result = sns_client.publish(request).sync().map_err(|e| {
            eprintln!("Attempt to publish {} alarm events failed!", len);
            // it is sort of lame that new_error only takes a &str as all we can
            // do is pass the description easily from map_err and description is deprecated
            ctx.new_error(e.description())
        })?;

        return Ok(format!("{} alarm events found", len));
    } else {
        return Ok("All Clear".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_req_extract() {
        let evnt_json = r###"
{
  "Records": [
    {
      "eventVersion": "2.0",
      "eventSource": "aws:s3",
      "awsRegion": "us-east-1",
      "eventTime": "1970-01-01T00:00:00.123Z",
      "eventName": "ObjectCreated:Put",
      "userIdentity": {
        "principalId": "EXAMPLE"
      },
      "requestParameters": {
        "sourceIPAddress": "127.0.0.1"
      },
      "responseElements": {
        "x-amz-request-id": "C3D13FE58DE4C810",
        "x-amz-id-2": "FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD"
      },
      "s3": {
        "s3SchemaVersion": "1.0",
        "configurationId": "testConfigRule",
        "bucket": {
          "name": "sourcebucket",
          "ownerIdentity": {
            "principalId": "EXAMPLE"
          },
          "arn": "arn:aws:s3:::mybucket"
        },
        "object": {
          "key": "HappyFace.jpg",
          "size": 1024,
          "urlDecodedKey": "HappyFace.jpg",
          "versionId": "version",
          "eTag": "d41d8cd98f00b204e9800998ecf8427e",
          "sequencer": "Happy Sequencer"
        }
      }
    }
  ]
}
"###;
        let event = serde_json::from_str(evnt_json);

        assert!(event.is_ok());

        let reqs = s3_get_obj_req_from_s3_event(event.unwrap());

        assert_eq!(1, reqs.len());

        assert_eq!("HappyFace.jpg", reqs[0].key);
        assert_eq!("sourcebucket", reqs[0].bucket);
    }
}
