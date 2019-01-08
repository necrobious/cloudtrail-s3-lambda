use lambda::error::HandlerError;
use rusoto_s3::GetObjectError;
use std::error::Error;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum CloudTrailError {
    InputJsonError,
    MissingS3Body,
    GenericS3GetObjectError(GetObjectError),
    S3GetObjectAuthError { key: String, bucket: String },
    S3BodyReaderError,
    AlarmError(String),
}

impl CloudTrailError {
    pub fn new_s3get_object_auth_error(key: String, bucket: String) -> Self {
        CloudTrailError::S3GetObjectAuthError {
            key: key.to_string(),
            bucket: bucket.to_string(),
        }
    }
}

impl Display for CloudTrailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::CloudTrailError::*;
        match self {
            InputJsonError => write!(f, "Expected an s3 event as input, got something else"),
            MissingS3Body => write!(f, "No Body found in S3 response"),
            GenericS3GetObjectError(e) => write!(f, "S3 GetObjectError occurred: {}", e),
            S3GetObjectAuthError { key, bucket } => write!(
                f,
                "Not Authorized to access the  {} object with the {} bucket in S3. \
                 Check that this Lambda's IAM Role has a policy with an effect of \
                 Allow to the s3:GetObject action on your S3 resource.",
                key, bucket
            ),
            S3BodyReaderError => write!(f, "Could not create reader off of S3 body"),
            AlarmError(msg) => write!(f, "AlarmError: {}", msg),
        }
    }
}

impl Error for CloudTrailError {}

impl CloudTrailError {
    pub fn convert_to_cloudtrail_error(&self, ctx: &lambda::Context) -> HandlerError {
        ctx.new_error(self.to_string().as_str())
    }
}
