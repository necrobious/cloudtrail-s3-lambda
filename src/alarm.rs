use jmespath::{Variable,Expression};

use std::fs::File;

use serde_json::{self, Value, Result as JsonResult};
use serde_json::map::Map;

use crate::alert;

lazy_static! {
    static ref ALARMS: Vec<alert::Alert> = {
        // TODO: look into jmespath_macros to move this into compiletime checking, right now
        // jmespath_macros requires nightly.
        vec!(
            alert::detect_root_activity(),
            alert::detect_cloudtrail_changes(),
            alert::detect_console_login_failures(),
            alert::detect_security_group_configuration_changes(),
            alert::detect_network_access_control_list_changes(),
            alert::detect_network_gateway_changes(),
            alert::detect_virtual_private_cloud_changes()
        )
    };
}

pub struct Alarms {
}

impl Alarms {
    pub fn detect(events:&Value) -> Result<Vec<Value>, String> {
        let data = Variable::from(events);
        let mut accum:Vec<Value> = Vec::new();
        for alarm in ALARMS.iter() {
            let key  = alarm.key.to_string();
            let expr = &alarm.expr;

            match expr.search(&data) {
                Err(e) => { return Err(e.to_string()) },
                Ok(var) => {

                    match var.as_array() {
                        Some(ref vec) => {
                            for rcvar in vec.iter() {
                                match serde_json::to_value(rcvar) {
                                    Ok(json_event) => {
                                        let mut om = Map::new();
                                        om.insert("event".to_string(),json_event);
                                        om.insert("alert".to_string(),Value::String(key.clone()));
                                        let json_object = Value::Object(om);
                                        accum.push(json_object);
                                    },
                                    Err(e) => { return Err(e.to_string()) }
                                }
                            }
                        },
                        None => {
                            return Err("Unexpected result: Expected an instance of jmespath::Variable::Array()".to_string())
                        }
                    }

                }
            }

        }
        Ok(accum)
    }
}

fn root_user_activity () -> &'static str  {
r###"
{
    "Records":[
        {
            "eventVersion":"1.05",
            "userIdentity":{
                "type":"IAMUser",
                "principalId":"AIDACKCEVSQ6C2EXAMPLE",
                "arn":"arn:aws:iam::111122223333:user/anaya",
                "accountId":"111122223333",
                "userName":"anaya"
            },
            "eventTime":"2018-08-29T16:24:34Z",
            "eventSource":"signin.amazonaws.com",
            "eventName":"ConsoleLogin",
            "awsRegion":"us-east-2",
            "sourceIPAddress":"192.0.2.0",
            "userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:62.0) Gecko/20100101 Firefox/62.0",
            "requestParameters":null,
            "responseElements":{
                "ConsoleLogin":"Success"
            },
            "additionalEventData":{
                "MobileVersion":"No",
                "LoginTo":"https://console.aws.amazon.com/sns",
                "MFAUsed":"No"
            },
            "eventID":"3fcfb182-98f8-4744-bd45-10a395ab61cb",
            "eventType": "AwsConsoleSignin"
        },
        {
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::111122223333:root",
                "accountId": "111122223333",
                "accessKeyId": ""
            },
            "eventTime": "2018-08-29T16:24:34Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:62.0) Gecko/20100101 Firefox/62.0",
            "requestParameters": null,
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "No"
            },
            "eventID": "deb1e1f9-c99b-4612-8e9f-21f93b5d79c0",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "111122223333"
        },
        {
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::111122223333:root",
                "accountId": "111122223333",
                "accessKeyId": ""
            },
            "eventTime": "2018-08-25T18:10:29Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
            "errorMessage": "Failed authentication",
            "requestParameters": null,
            "responseElements": {
                "ConsoleLogin": "Failure"
            },
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "No"
            },
            "eventID": "a4fbbe77-91a0-4238-804a-64314184edb6",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "111122223333"
        }
]}
"###
}

#[test]
fn test_expressions () {

	let root_login_events_parse_result:JsonResult<Value> = serde_json::from_str(root_user_activity());

    assert!(root_login_events_parse_result.is_ok());

	let events = root_login_events_parse_result.unwrap();

    let r = Alarms::detect(&events);

    assert!(r.is_ok());

    let rv = r.unwrap();

    assert_eq!(3,rv.len());

	let expr_parse_result = jmespath::compile("alert");

    assert!(expr_parse_result.is_ok());

    let expr = expr_parse_result.unwrap();

    let mut root_activity_counter = 0;
    let mut login_failure_counter = 0;

    for e in rv {

        let data = Variable::from(e);

        let query_result = expr.search(data);

        assert!(query_result.is_ok());

        let query = query_result.unwrap();

        assert!(query.is_string());

        let query_key = query.as_string().unwrap();

        if query_key == "DETECT_ROOT_ACTIVITY" {
            root_activity_counter += 1;
        }
        if query_key == "DETECT_CONSOLE_LOGIN_FAILURES" {
            login_failure_counter += 1;
        }

    }

    assert_eq!(2, root_activity_counter);
    assert_eq!(1, login_failure_counter);
}

#[test]
fn test_root_user_activity_detection () {

	// see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
    let root_login_events = root_user_activity();

	let root_login_events_parse_result:JsonResult<Value> = serde_json::from_str(root_login_events);

    assert!(root_login_events_parse_result.is_ok());

	let events = root_login_events_parse_result.unwrap();

	let expr_parse_result = jmespath::compile("Records[?userIdentity.type == 'Root' && userIdentity.invokedBy == null && eventType != 'AwsServiceEvent']");

    assert!(expr_parse_result.is_ok());

    let expr = expr_parse_result.unwrap();

    let data = Variable::from(events);

    let query_result = expr.search(data);

    assert!(query_result.is_ok());

    let query = query_result.unwrap();

    assert!(query.is_array());

    let v = query.as_array().unwrap();

    assert_eq!(2, v.len());

}
