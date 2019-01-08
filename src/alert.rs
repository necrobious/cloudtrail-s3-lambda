use jmespath::Expression;

pub struct Alert {
    pub key: &'static str,
    pub expr: Expression<'static>,
}

pub fn detect_root_activity() -> Alert {
    Alert {
        key: "DETECT_ROOT_ACTIVITY",
        expr: jmespath::compile("Records[?userIdentity.type == 'Root' && userIdentity.invokedBy == null && eventType != 'AwsServiceEvent']").unwrap()
    }
}

pub fn detect_cloudtrail_changes() -> Alert {
    Alert {
        key: "DETECT_CLOUDTRAIL_CHANGES",
        expr: jmespath::compile("Records[?eventName == 'CreateTrail' || eventName == 'UpdateTrail' || eventName == 'DeleteTrail' || eventName == 'StartLogging' || eventName == 'StopLogging']").unwrap()
    }
}

pub fn detect_console_login_failures() -> Alert {
    Alert {
        key: "DETECT_CONSOLE_LOGIN_FAILURES",
        expr: jmespath::compile(
            "Records[?eventName == 'ConsoleLogin' && errorMessage == 'Failed authentication']",
        )
        .unwrap(),
    }
}

pub fn detect_security_group_configuration_changes() -> Alert {
    Alert {
        key: "DETECT_SECURITY_GROUP_CONFIGURATION_CHANGES",
        expr: jmespath::compile("Records[?eventName == 'AuthorizeSecurityGroupIngress' || eventName == 'AuthorizeSecurityGroupEgress' || eventName == 'RevokeSecurityGroupIngress' || eventName == 'RevokeSecurityGroupEgress' || eventName == 'CreateSecurityGroup' || eventName == 'DeleteSecurityGroup']").unwrap()
    }
}

pub fn detect_network_access_control_list_changes() -> Alert {
    Alert {
        key: "DETECT_NETWORK_ACCESS_CONTROL_LIST_CHANGES",
        expr: jmespath::compile("Records[?eventName == 'CreateNetworkAcl' || eventName == 'CreateNetworkAclEntry' || eventName == 'DeleteNetworkAcl' || eventName == 'DeleteNetworkAclEntry' || eventName == 'ReplaceNetworkAclEntry' || eventName == 'ReplaceNetworkAclAssociation']").unwrap()
    }
}

pub fn detect_network_gateway_changes() -> Alert {
    Alert {
        key: "DETECT_NETWORK_GATEWAY_CHANGES",
        expr: jmespath::compile("Records[?eventName == 'CreateCustomerGateway' || eventName == 'DeleteCustomerGateway' || eventName == 'AttachInternetGateway' || eventName == 'CreateInternetGateway' || eventName == 'DeleteInternetGateway' || eventName == 'DetachInternetGateway']").unwrap()
    }
}

pub fn detect_virtual_private_cloud_changes() -> Alert {
    Alert {
        key: "DETECT_VIRTUAL_PRIVATE_CLOUD_CHANGES",
        expr: jmespath::compile("Records[?eventName == 'CreateVpc' || eventName == 'DeleteVpc' || eventName == 'ModifyVpcAttribute' || eventName == 'AcceptVpcPeeringConnection' || eventName == 'CreateVpcPeeringConnection' || eventName == 'DeleteVpcPeeringConnection' || eventName == 'RejectVpcPeeringConnection' || eventName == 'AttachClassicLinkVpc' || eventName == 'DetachClassicLinkVpc' || eventName == 'DisableVpcClassicLink' || eventName == 'EnableVpcClassicLink']").unwrap()
    }
}
