# LambdaConatinment_EC2s_Subnets
AWS EC2, Subnet containment script for Lambda function

What It Does

    Ensures a Containment-SG exists in the VPC with ports 3999, 17472, 22 open.

    Replaces the SGs on the target EC2 instances with Containment-SG.

    Optionally shuts down EC2 instances.

    Optionally locks down NACLs for the subnets:

        Backs up rules to S3.

        Removes existing rules except default.

        Allows only forensic ports and then deny-all.

How to Use It

    Deploy as a Lambda function with permissions for:
        ec2:DescribeInstances, ec2:ModifyNetworkInterfaceAttribute, ec2:StopInstances
        ec2:DescribeSecurityGroups, ec2:CreateSecurityGroup, ec2:AuthorizeSecurityGroupIngress/Egress
        ec2:DescribeNetworkAcls, ec2:DeleteNetworkAclEntry, ec2:CreateNetworkAclEntry
        s3:PutObject (to backup NACL rules)

    Pass an event JSON when invoking:
    {
  "vpc_id": "vpc-0319c7b9b551e2263",
  "subnet_ids": ["subnet-01d9e7d14a9c91e0e"],
  "instance_ids": ["i-0abcd1234567890a", "i-0efgh9876543210b"],
  "shutdown_instances": true,
  "contain_nacls": true
}
