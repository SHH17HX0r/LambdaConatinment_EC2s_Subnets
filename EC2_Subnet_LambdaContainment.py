import boto3
from datetime import datetime
import json

# AWS clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

# Configurations
ALLOWED_CIDR = '172.31.0.0/16'
FORENSIC_PORTS = [3999, 17472, 22]  # FTK, Tanium, SSH
BACKUP_BUCKET = 'forensic-nacl-backups'  # bucket for NACL backups


def backup_nacl_rules(nacl_id):
    """Backup NACL rules to S3 before modifying"""
    nacl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    key = f"nacl-backups/{nacl_id}_{timestamp}.json"
    s3.put_object(Bucket=BACKUP_BUCKET, Key=key, Body=json.dumps(nacl['Entries'], indent=2))
    print(f"[~] Backed up NACL {nacl_id} to s3://{BACKUP_BUCKET}/{key}")


def create_or_get_containment_sg(vpc_id):
    """Get or create the Containment Security Group"""
    response = ec2.describe_security_groups(
        Filters=[
            {'Name': 'group-name', 'Values': ['Containment-SG']},
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ]
    )
    if response['SecurityGroups']:
        sg_id = response['SecurityGroups'][0]['GroupId']
        print(f"[=] Reusing Containment-SG: {sg_id}")
    else:
        sg = ec2.create_security_group(
            GroupName='Containment-SG',
            Description='Forensic-only access (FTK, Tanium, SSH)',
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']
        print(f"[+] Created Containment-SG: {sg_id}")

    # Authorize ports
    ip_permissions = [{
        'IpProtocol': 'tcp',
        'FromPort': port,
        'ToPort': port,
        'IpRanges': [{'CidrIp': ALLOWED_CIDR}]
    } for port in FORENSIC_PORTS]

    try:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ip_permissions)
        ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=ip_permissions)
    except ec2.exceptions.ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            print("[!] SG rules already exist, skipping duplicate rules")
        else:
            raise

    return sg_id


def contain_ec2s(instance_ids, containment_sg_id, shutdown_instances):
    """Apply containment SG to EC2s and optionally shut them down"""
    for instance_id in instance_ids:
        eni = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]
        eni_id = eni['NetworkInterfaceId']

        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[containment_sg_id]
        )
        print(f"[+] Applied Containment-SG to {instance_id}")

    if shutdown_instances:
        ec2.stop_instances(InstanceIds=instance_ids)
        print(f"[!] Shutdown triggered for EC2 instances: {instance_ids}")


def contain_nacls(subnet_ids):
    """Contain subnet-level NACLs"""
    for subnet_id in subnet_ids:
        nacls = ec2.describe_network_acls(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )
        if not nacls['NetworkAcls']:
            print(f"[!] No NACL found for subnet {subnet_id}")
            continue

        nacl = nacls['NetworkAcls'][0]
        nacl_id = nacl['NetworkAclId']
        print(f"[*] Containing NACL {nacl_id} for subnet {subnet_id}")

        # Backup
        backup_nacl_rules(nacl_id)

        # Clear existing rules except default 32767
        for entry in nacl['Entries']:
            if entry['RuleNumber'] == 32767:
                continue
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=entry['RuleNumber'],
                Egress=entry['Egress']
            )

        # Add forensic-only rules
        rule_num = 100
        for port in FORENSIC_PORTS:
            for egress in [False, True]:
                ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule_num,
                    Protocol='6',  # TCP
                    RuleAction='allow',
                    Egress=egress,
                    CidrBlock=ALLOWED_CIDR,
                    PortRange={'From': port, 'To': port}
                )
                rule_num += 1

        # Add deny-all
        for egress in [False, True]:
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=200,
                Protocol='-1',
                RuleAction='deny',
                Egress=egress,
                CidrBlock='0.0.0.0/0'
            )
        print(f"[+] NACL containment applied for subnet {subnet_id}")


def main():
    # Inputs
    vpc_id = input("Enter VPC ID: ").strip()
    subnet_ids = input("Enter subnet IDs (comma-separated): ").strip().split(",")
    instance_ids = input("Enter EC2 instance IDs (comma-separated): ").strip().split(",")
    shutdown_instances = input("Shutdown instances? (yes/no): ").lower() == 'yes'
    contain_subnets = input("Contain subnets with NACLs? (yes/no): ").lower() == 'yes'

    # 1. Create/get containment SG
    containment_sg_id = create_or_get_containment_sg(vpc_id)

    # 2. Contain EC2s
    contain_ec2s(instance_ids, containment_sg_id, shutdown_instances)

    # 3. Optionally contain subnet-level NACLs
    if contain_subnets:
        contain_nacls(subnet_ids)


if __name__ == "__main__":
    main()
