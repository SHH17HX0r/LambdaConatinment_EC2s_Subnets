# LambdaConatinment_EC2s_Subnets
AWS EC2, Subnet containment script for Lambda function

Takes user inputs:

    VPC ID
    Subnet IDs
    EC2 instance IDs
    Whether to shutdown instances
    Whether to contain subnet NACLs

Creates or reuses a Containment-SG:

    Only allows ports 3999, 17472, and 22 to ALLOWED_CIDR.

Applies the Containment-SG to the provided EC2 instances’ ENIs.

Optionally shuts down the EC2 instances.

Optionally modifies the subnet NACLs:

    Backs up the original NACL rules to S3.
    Removes all existing rules (except default 32767).
    Adds forensic-only allow rules.
    Adds deny-all catch-all rules.
