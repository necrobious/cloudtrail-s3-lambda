#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate lambda_runtime as lambda;

#[macro_use]
extern crate log;

extern crate simple_logger;
extern crate aws_lambda_events;
extern crate rusoto_core;
extern crate rusoto_sns;
extern crate libflate;
extern crate jmespath;

use std::env;
use std::fmt;
use std::default::Default;
use serde_json::{self, Value};
use serde_json::de::from_reader;
use serde_json::error::Error as SerdeError;
use aws_lambda_events::event::s3::S3Event;

use rusoto_core::Region;
use rusoto_core::request::BufferedHttpResponse;
use rusoto_s3::{S3, S3Client, GetObjectRequest, GetObjectOutput, GetObjectError, StreamingBody};
use rusoto_sns::{Sns, SnsClient, PublishInput, PublishResponse};
use libflate::gzip::Decoder;

use lambda::error::HandlerError;
use std::error::Error;

mod alert;
mod alarm;

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

fn s3_get_obj_req_from_s3_event (s3_event:S3Event) -> Vec<GetObjectRequest> {
    let mut res = Vec::new();
    let recs = s3_event.records;
    for rec in recs.iter() {
        match (&rec.s3.bucket.name, &rec.s3.object.key) {
            (None, _) | (_,None) => { continue },
            (Some(bucket), Some(key)) => {
                res.push(GetObjectRequest {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    ..Default::default()
                })
            }
        }
    }
    res
}

fn do_error <E> (e: E, ctx:lambda::Context) -> Result<String, HandlerError> where E: ToString {
    Err(ctx.new_error(e.to_string().as_str()))
}


fn my_handler(input: Value, ctx: lambda::Context) -> Result<String, HandlerError> {
    //let alert_topic_arn  = env::var("ALERTS_TOPIC_ARN").map_err(|e| ctx.new_error(e.to_string().as_str()))?;
    let alert_topic_arn  = env::var("ALERTS_TOPIC_ARN");
    if alert_topic_arn.is_err() {
        return do_error("Expected ALERTS_TOPIC_ARN to be set in env", ctx);
    }

    let sns_client = SnsClient::new(Region::UsWest2);
    let s3_client = S3Client::new(Region::UsWest2);

    let s3_event = serde_json::from_value(input);
    if s3_event.is_err() {
        return do_error("Expected an s3 event as input, got someting else", ctx)
    }

    let mut findings:Vec<Value> = Vec::new();

    for s3_req in s3_get_obj_req_from_s3_event(s3_event.unwrap()).iter() {
        match s3_client.get_object(s3_req.clone()).sync() {
            Ok(GetObjectOutput{body:Some(stream),..}) => {
                let mut reader = stream.into_blocking_read();
                match Decoder::new(&mut reader) {
                    Ok(decoder) => {
                        let json:Result<Value, SerdeError>  = from_reader(decoder);
                        match json {
                            Ok(value) => {
                                match alarm::Alarms::detect(&value) {
                                    Ok(matched_events) => {
                                        for event in matched_events.iter() {
                                            findings.push(event.clone())
                                        }
                                    },
                                    Err(e) => { return do_error(e,ctx) }
                                }
                            },
                            Err(e) => { return do_error(e,ctx) },
                        }
                    },
                    Err(e) => return do_error(e,ctx),
                }
            },
            Ok(GetObjectOutput{body:None,..}) => {
                return do_error("Valid response from S3, but no data. Exiting",ctx) // Err(ctx.new_error("Valid response from S3, but no data. Exiting"))
            },
            Err(GetObjectError::Unknown(BufferedHttpResponse{status: s, ..})) if s.as_u16() == 403 => {
                let msg = format!("Not Authorized to access the  {} object with the {} bucket in S3. \
                           Check that this Lambda's IAM Role has a policy with an effect of \
                           Allow to the s3:GetObject action on your S3 resource.", s3_req.key, s3_req.bucket );
                return do_error(msg.as_str(),ctx)
            },
            Err(e) => { return do_error(e.to_string(), ctx) /*Err(ctx.new_error(e.to_string().as_str()))*/ },
        }
    }

    let len = findings.len();

    if len > 0 {
        let msg_json = Value::Array(findings);
        let msg = serde_json::to_string(&msg_json);//.map_err(|e| ctx.new_error(e.to_string().as_str()))?;
        if msg.is_err() {
            return do_error("Unable to serialize findings into a JSON string", ctx)
        }

        let request = PublishInput {
            message: msg.unwrap(),
            topic_arn: Some(alert_topic_arn.unwrap()),
            ..Default::default()
        };

        let publish_result = sns_client.publish(request).sync();
        if publish_result.is_err() {
            return do_error(format!("Attempt to publish {} alarm events failed!", len), ctx);
        }
        return Ok(format!("{} alarm events found", len));

    }
    else {
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

