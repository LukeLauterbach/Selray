import boto3
from botocore.exceptions import ClientError
import time
import paramiko
import os
import requests
import argparse
import logging
from rich.table import Table
from rich.console import Console
from rich.text import Text
from tqdm import tqdm
import socket
import ipaddress
import textwrap
from concurrent.futures import ThreadPoolExecutor


def main(num_proxies=5, clean=False, debug=False):
    clean, num_proxies, aws_mode, debug, list_mode = parse_arguments()
    setup_debugging(debug)
    ec2_session = get_ec2_session()
    if clean:
        terminate_instances_in_security_group(ec2_session, "Selray")
        exit()
    elif list_mode:
        instances = list_instances(ec2_session, "Selray")
        exit()
    if aws_mode:
        proxy_setup(ec2_session, num_proxies)


def setup_debugging(debug):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='[%(levelname)s] %(message)s',
        force=True
    )


def parse_arguments():
    parser = argparse.ArgumentParser(description="Manage EC2 instances")

    parser.add_argument("-aws", action="store_true", help="Create and use AWS proxies")
    parser.add_argument("--clean", action="store_true", help="Clean up all instances")
    parser.add_argument("--list", action="store_true", help="List proxy instances")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-n", "--num_proxies", type=int, default=1, help="Number of proxies to create")
    args = parser.parse_args()
    return args.clean, args.num_proxies, args.aws, args.debug, args.list


def get_ec2_session(region_name=None, access_key=None, secret_key=None, session_token=None):
    try:
        if access_key and secret_key:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region_name
            )
        else:
            session = boto3.Session(region_name=region_name)

        sts = session.client('sts')
        sts.get_caller_identity()
        return session
    except Exception as e:
        return None


def refresh_instance_ip(ec2_session, instance_id):
    ec2 = ec2_session.client('ec2')
    logging.debug(f"Stopping instance {instance_id}...")
    ec2.stop_instances(InstanceIds=[instance_id])
    waiter = ec2.get_waiter('instance_stopped')
    waiter.wait(InstanceIds=[instance_id])
    logging.debug("Instance stopped.")

    logging.debug(f"Starting instance {instance_id}...")
    ec2.start_instances(InstanceIds=[instance_id])
    waiter = ec2.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance_id])
    logging.debug("Instance started and running.")

    response = ec2.describe_instances(InstanceIds=[instance_id])
    new_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')

    if not new_ip:
        raise Exception("Public IP not assigned after restart.")

    logging.debug(f"New public IP for {instance_id}: {new_ip}")

    wait_for_instance_to_be_ready(new_ip)

    return new_ip, f"http://{new_ip}:8888"


def list_instances(ec2_session, security_group_name, region="us-east-2"):
    ec2_client = ec2_session.client('ec2')
    ec2_resource = ec2_session.resource('ec2')

    # Get the security group ID from the name
    response = ec2_client.describe_security_groups(
        Filters=[{'Name': 'group-name', 'Values': [security_group_name]}]
    )
    if not response['SecurityGroups']:
        logging.debug(f"No security group found with name '{security_group_name}'")
        return []

    sg_id = response['SecurityGroups'][0]['GroupId']

    # Find instances in that security group
    instances = ec2_resource.instances.filter(
        Filters=[
            {'Name': 'instance.group-id', 'Values': [sg_id]},
            {'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopped']}
        ]
    )

    instance_list = []
    for instance in instances:
        instance_list.append({
            'id': instance.id,
            'state': instance.state['Name'],
            'public_ip': instance.public_ip_address,
            'private_ip': instance.private_ip_address,
            'launch_time': instance.launch_time.strftime('%Y-%m-%d %H:%M:%S')
        })

    if not instance_list:
        print(f"No {security_group_name} AWS instances found.")
        return []

    # Print table
    console = Console()
    table = Table(title=f"AWS Instances in Security Group: {security_group_name}")
    table.add_column("Instance ID", style="cyan")
    table.add_column("State", style="green")
    table.add_column("Public IP", style="magenta")
    table.add_column("Launch Time", style="yellow")

    for inst in instance_list:
        state_style = "green" if inst['state'] == "running" else "red"
        state_text = Text(inst['state'], style=state_style)
        table.add_row(inst['id'], inst['state'], str(inst['public_ip']), inst['launch_time'])

    console.print(table)

    return instance_list


def proxy_setup(ec2_session, num_proxies=5):
    ssh_key_name = "Selray"
    tasks = ['Creating Security Group', 'Finding AWS OS Image',
             f'Creating {num_proxies} EC2 Instances', 'Waiting for Proxies to be Available']
    with tqdm(total=len(tasks), desc='Starting...', dynamic_ncols=True) as bar:

        bar.set_description(tasks[0])
        my_ip = create_security_group(ec2_session, "Selray")
        bar.update(1)

        bar.set_description(tasks[1])
        ec2_ami = find_os_ami(ec2_session)
        bar.update(1)

        bar.set_description(tasks[2])
        ec2_instances = create_ec2_instances(ec2_session, ssh_key_name, ec2_ami, num_proxies)
        bar.update(1)

        bar.set_description(tasks[3])
        wait_for_all_instances(ec2_instances)
        bar.update(1)

    return ec2_instances


def find_os_ami(ec2_session):
    ec2 = ec2_session.client('ec2')
    # Get the current region
    region = ec2.meta.region_name

    # Describe images (AMIs) with 'alpine' in their name for the current region, without owner filter
    response = ec2.describe_images(
        Filters=[{
            'Name': 'name',
            'Values': ['*alpine*']
        },
        {
            'Name': 'architecture',
            'Values': ['x86_64']
        }]
    )

    # Check if images are found and sort by creation date
    if response['Images']:
        # Sort images by creation date and pick the latest one
        latest_image = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
        logging.debug(f"Found latest Alpine Linux AMI: {latest_image['Name']} with AMI ID: {latest_image['ImageId']}")
        return latest_image['ImageId']
    else:
        logging.debug(f"No Alpine Linux AMIs found in region {region}. You may need to check for other image IDs manually.")
        return None


def wait_for_instance_to_be_ready(ec2_instance, timeout=120, check_interval=5, port=8888):
    """
    Repeatedly checks if port 8888 is open on the instance until timeout.

    :param ec2_instance: Dictionary with at least 'ip' key.
    :param timeout: Total time (in seconds) to keep checking.
    :param check_interval: Time between checks (in seconds).
    :return: True if port is open before timeout, else False.
    """
    if isinstance(ec2_instance, dict):
        ip = ec2_instance['ip']
    else:
        ip = ec2_instance
    start_time = time.time()

    while (time.time() - start_time) < timeout:
        if is_port_open(ip, port):
            logging.debug(f"✅ Port {port} is open on {ip}")
            return True
        else:
            logging.debug(f"⏳ Waiting for port {port} on {ip} to open...")
            time.sleep(check_interval)

    logging.error(f"❌ Timeout: Port {port} not open on {ip} after {timeout} seconds")
    return False


def is_port_open(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def wait_for_all_instances(ec2_instances):
    with ThreadPoolExecutor(max_workers=len(ec2_instances)) as ex:
        ex.map(wait_for_instance_to_be_ready, ec2_instances)


def build_user_data_alpine(allowed_ip: str, port: int = 8888) -> str:
    # Shell script works with cloud-init present. Keep it small.
    return textwrap.dedent(f"""\
    #!/bin/sh
    set -eux
    apk update
    apk add --no-cache tinyproxy
    # Minimal restrictive config
    sed -i 's/^#\\?Port .*/Port {port}/' /etc/tinyproxy/tinyproxy.conf
    # reset Allow lines and add only localhost and your IP
    sed -i '/^Allow /d' /etc/tinyproxy/tinyproxy.conf
    printf "Allow 127.0.0.1\\nAllow {allowed_ip}/32\\n" >> /etc/tinyproxy/tinyproxy.conf
    # keep common CONNECT ports
    grep -q '^ConnectPort 443' /etc/tinyproxy/tinyproxy.conf || printf "ConnectPort 443\\n" >> /etc/tinyproxy/tinyproxy.conf
    grep -q '^ConnectPort 563' /etc/tinyproxy/tinyproxy.conf || printf "ConnectPort 563\\n" >> /etc/tinyproxy/tinyproxy.conf
    rc-update add tinyproxy default
    rc-service tinyproxy restart
    """)

def _resolve_sg_ids(ec2_client, group_names, vpc_id=None):
    filters = [{'Name': 'group-name', 'Values': group_names}]
    if vpc_id:
        filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
    resp = ec2_client.describe_security_groups(Filters=filters)
    return [sg['GroupId'] for sg in resp['SecurityGroups']]

def _default_vpc_id(ec2_client):
    vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])['Vpcs']
    return vpcs[0]['VpcId'] if vpcs else None

def get_public_ipv4(timeout=2.0) -> str:
    # Endpoints that return plain IPv4 text with a trailing newline
    endpoints = [
        "https://checkip.amazonaws.com",
        "https://ipv4.icanhazip.com",
        "https://api.ipify.org",      # defaults to IPv4 for most clients
    ]
    for url in endpoints:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "selray/1.0"})
            ip_txt = r.text.strip()
            ip = ipaddress.ip_address(ip_txt)  # raises if invalid
            if ip.version == 4:
                return str(ip)
        except Exception:
            continue
    raise RuntimeError("Could not determine public IPv4 address")

def cidr32(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip.version != 4:
        raise ValueError(f"Expected IPv4 but got {ip}")
    return f"{ip}/32"



def create_ec2_instances(ec2_session, ssh_key_name, ami_id, num_proxies=5, my_ip=None):
    ec2_res = ec2_session.resource('ec2')
    ec2_cli = ec2_session.client('ec2')

    if not my_ip:
        my_ip = get_public_ipv4()             # validated IPv4 like "203.0.113.7"
    my_cidr = cidr32(my_ip)

    # Resolve SG IDs - do not pass names here
    vpc_id = _default_vpc_id(ec2_cli)
    sg_ids = _resolve_sg_ids(ec2_cli, ['default', 'Selray'], vpc_id=vpc_id)

    # Keep root volume a bit bigger for updates and logs
    block_device = [{
        'DeviceName': '/dev/sda1',
        'Ebs': {
            'VolumeSize': 2,          # 2 GiB is still tiny but safer than 1
            'VolumeType': 'gp3',
            'DeleteOnTermination': True
        }
    }]

    user_data = build_user_data_alpine(my_ip, port=8888) if my_ip else None

    # Launch
    instances = ec2_res.create_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=num_proxies,
        MaxCount=num_proxies,
        KeyName=ssh_key_name,
        BlockDeviceMappings=block_device,
        SecurityGroupIds=sg_ids,
        UserData=user_data  # boto3 base64 encodes automatically
    )

    ec2_instances = []
    for inst in instances:
        inst.wait_until_running()
        inst.reload()
        ec2_instances.append({
            'type': 'AWS',
            'id': inst.id,
            'ip': inst.public_ip_address,
            'url': f"http://{inst.public_ip_address}:8888"
        })

    return ec2_instances


def create_security_group(ec2_session, group_name):
    ec2 = ec2_session.client('ec2')

    # Get current external IP
    my_ip = requests.get('https://checkip.amazonaws.com').text.strip()

    # Check if the security group "Selray" exists
    response = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [group_name]}])

    if response['SecurityGroups']:
        logging.debug(f"Security group '{group_name}' already exists.")
    else:
        logging.debug(f"Security group '{group_name}' not found. Creating it now...")

        # Create the security group
        create_response = ec2.create_security_group(
            GroupName=group_name,
            Description='Security group that allows any port from my current external IP.',
        )

        security_group_id = create_response['GroupId']
        logging.debug(f"Created security group with ID: {security_group_id}")

        # Allow inbound traffic on all ports from the current external IP
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[{
                'IpProtocol': '-1',  # This allows all ports
                'FromPort': 0,
                'ToPort': 65535,
                'IpRanges': [{'CidrIp': f'{my_ip}/32'}]
            }]
        )
        logging.debug(f"Added inbound rule allowing all ports from {my_ip}/32 to 'Selray'.")

    return my_ip


def terminate_instances_in_security_group(ec2_session, security_group_name):
    ec2_resource = ec2_session.resource('ec2')
    ec2_client = ec2_session.client('ec2')

    # Get the security group ID from the name
    response = ec2_client.describe_security_groups(
        Filters=[{'Name': 'group-name', 'Values': [security_group_name]}]
    )
    if not response['SecurityGroups']:
        logging.debug(f"No security group found with name '{security_group_name}'")
        return

    sg_id = response['SecurityGroups'][0]['GroupId']

    # Find instances in that security group
    instances = ec2_resource.instances.filter(
        Filters=[
            {'Name': 'instance.group-id', 'Values': [sg_id]},
            {'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopped']}
        ]
    )

    instance_ids = []

    for instance in instances:
        # Ensure volumes are deleted on termination
        for dev in instance.block_device_mappings:
            device_name = dev.get('DeviceName')
            ebs = dev.get('Ebs', {})
            if device_name and 'VolumeId' in ebs:
                instance.modify_attribute(
                    BlockDeviceMappings=[
                        {
                            'DeviceName': device_name,
                            'Ebs': {
                                'DeleteOnTermination': True
                            }
                        }
                    ]
                )

        instance_ids.append(instance.id)

    if instance_ids:
        logging.debug(f"Terminating instances: {instance_ids}")
        ec2_resource.instances.filter(InstanceIds=instance_ids).terminate()
    else:
        logging.debug(f"No instances found in security group '{security_group_name}'.")


def stop_ec2_instance(ec2_session, instance_id):
    """
    Stops an EC2 instance by instance ID.

    :param ec2: EC2 instance to use.
    :param instance_id: The ID of the EC2 instance to stop (e.g., 'i-0123456789abcdef0').
    """

    ec2 = ec2_session.client('ec2')

    try:
        response = ec2.stop_instances(InstanceIds=[instance_id])
        logging.debug(f"Stopping instance: {instance_id}")

        # Wait until the instance is stopped
        waiter = ec2.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])
        logging.debug(f"Instance {instance_id} has fully stopped.")

        return response
    except Exception as e:
        logging.debug(f"Error stopping instance {instance_id}: {e}")
        return None


import boto3
import logging


def start_ec2_instance(ec2_session, instance_id):
    """
    Starts an EC2 instance by instance ID and returns the new public IP address.

    :param ec2: EC2 instance to use.
    :param instance_id: The ID of the EC2 instance to start (e.g., 'i-0123456789abcdef0').
    :return: The public IP address of the instance, or a message if already running.
    """

    ec2 = ec2_session.client('ec2')

    try:
        status_response = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        state = status_response['InstanceStatuses'][0]['InstanceState']['Name']
        if state == "running":
            logging.debug(f"Instance {instance_id} is already running.")
            ip = get_instance_ip(ec2_session, instance_id)
            return ip, f"http://{ip}:8888"

        ec2.start_instances(InstanceIds=[instance_id])
        logging.debug(f"Starting instance: {instance_id}")

        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        logging.debug(f"Instance {instance_id} is now running.")

        # Retrieve and return the public IP address
        ip = get_instance_ip(ec2_session, instance_id)
        logging.debug(f"Instance {instance_id} public IP: {ip}")

        # Wait for the proxy to come up (and be available on port 8888)
        wait_for_instance_to_be_ready(ip)

        return ip, f"http://{ip}:8888"

    except Exception as e:
        logging.error(f"❌ Error starting instance {instance_id}: {e}")
        return None, None


def get_instance_ip(ec2_session, instance_id):
    """
    Retrieves the public IP address of an EC2 instance.

    :param ec2_client: A boto3 EC2 client.
    :param instance_id: The ID of the instance.
    :return: The public IP address, or None if not assigned.
    """

    ec2 = ec2_session.client('ec2')

    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])['Reservations']
        instance = reservations[0]['Instances'][0]
        ip_address = instance.get('PublicIpAddress')

        if ip_address:
            logging.debug(f"Instance {instance_id} public IP: {ip_address}")
            return ip_address
        else:
            logging.debug(f"No public IP assigned to instance {instance_id}.")
            return None
    except Exception as e:
        logging.debug(f"Error retrieving IP address for instance {instance_id}: {e}")
        return None


if __name__ == "__main__":
    main()