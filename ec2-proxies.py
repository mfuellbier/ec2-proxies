#!/bin/python

import argparse
import boto3
import botocore
import logging
import re
import subprocess
import time


def stop(args, loglevel, DRYRUN=False):
    ec2 = boto3.client('ec2')
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    try:
        reservations = response["Reservations"]
    except IndexError:
        reservations = []
    instances = [instance for reservation in reservations for instance in reservation["Instances"]]

    count_running_instances = len(instances)
    count_all_instances = len(instances)

    if count_running_instances == 0:
        print("No Instances running.")
        return 0
    else:
        print("Terminate following Instances: ")
        status(args, loglevel, state="running")
        instance_ids = []
        for instance in instances:
            instance_ids.append(instance["InstanceId"])
        ec2.terminate_instances(InstanceIds=instance_ids, DryRun=DRYRUN)

    while not count_running_instances == 0:
        time.sleep(1)
        response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['shutting-down']}])
        reservations = response["Reservations"]
        instances = [instance for reservation in reservations for instance in reservation["Instances"]]
        if len(instances) < count_running_instances:
            count_running_instances = len(instances)
            print(str(count_running_instances) + "/" + str(count_all_instances) + " Instances up.")
    print("All Instances down.")


def start(args, loglevel, DRYRUN=False):
    ec2 = boto3.client('ec2')
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)

    if int(args.number) < 1:
        logging.error("Number of instances must be greater 0!")
        return 1

    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    reservations = response["Reservations"]
    instances = [instance for reservation in reservations for instance in reservation["Instances"]]
    count_running_instances = len(instances)

    if instances == []:
        if args.number == 1:
            print("No instances running yet. Run " + str(args.number) + " instance...")
        else:
            print("No instances running yet. Run " + str(args.number) + " instances...")
    elif len(instances) == 1:
        if args.number == 1:
            print("One instance is already running. Run " + str(args.number) + " new instance...")
        else:
            print("One instance is already running. Run " + str(args.number) + " new instances...")
    else:
        if args.number == 1:
            print(str(len(instances)) + " instances are already running. Run " + str(args.number) + " new instance...")
        else:
            print(str(len(instances)) + " instances are already running. Run " + str(args.number) + " new instances...")

    try:
        ec2.run_instances(ImageId=args.imageid, InstanceType=args.instancetype, KeyName=args.keyname, MaxCount=int(args.number), MinCount=int(args.number), DryRun=DRYRUN)
    except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as err:
        logging.error("EC2 run instance failed!")
        print(str(err))
        return 1

    count_pending_instances = int(args.number)
    count_all_instances = count_running_instances + count_pending_instances
    while not count_pending_instances == 0:
        response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['pending']}])
        reservations = response["Reservations"]
        instances = [instance for reservation in reservations for instance in reservation["Instances"]]
        if count_pending_instances > len(instances):
            response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            reservations = response["Reservations"]
            running_instances = [instance for reservation in reservations for instance in reservation["Instances"]]
            count_running_instances = len(running_instances)
            print(str(count_running_instances) + "/" + str(count_all_instances) + " Instances up.")
            count_pending_instances = len(instances)
        time.sleep(1)
    print("All Instances up.")
    authorize_security_groups(args)
    ssh_up(args)
    status(args, loglevel)


def status(args, loglevel, state=None):
    ec2 = boto3.client('ec2')
    if state:
        response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': [state]}])
    else:
        response = ec2.describe_instances()
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    reservations = response["Reservations"]
    instances = [instance for reservation in reservations for instance in reservation["Instances"]]

    print(" State ".ljust(len(" shutting-down ")) + "|" + " InstanceID ".ljust(len(" i-088807572db49585c ")) + "|" + " PublicIP ".ljust(len(" 123.123.123.123 ")) + "|" + " GroupId ".ljust(len(" sg-b4152fc4 ")) + "|" + " Port ".ljust(len("65535")))
    print("-" * 76)
    ssh_ips = ssh_dict()
    for instance in instances:
        try:
            instance_ip = instance["NetworkInterfaces"][0]["Association"]["PublicIp"]
        except:
            instance_ip = ""
        try:
            port = ssh_ips[instance_ip]
        except KeyError:
            port = [""]
        try:
            groupid = instance["NetworkInterfaces"][0]["Groups"][0]["GroupId"]
        except (KeyError, IndexError):
            groupid = ""
        print(" " + instance["State"]["Name"].ljust(len("shutting-down ")) + "| " + instance["InstanceId"] + " | " + instance_ip.ljust(len("123.123.123.123")) + " | " + groupid.ljust(len("sg-b4152fc4")) + " | " + port[0])


def ssh_up(args):
    print("Connect to EC2 instances for SSH tunnel...")
    ec2 = boto3.client('ec2')
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    try:
        reservations = response["Reservations"]
    except IndexError:
        reservations = []
    instance_ips = [instance["NetworkInterfaces"][0]["Association"]["PublicIp"] for reservation in reservations for instance in reservation["Instances"]]

    port = args.port
    for ip in instance_ips:
        return_code = 1
        while port_busy(port):
            port = str(int(port) + 1)
        while not return_code == 0:
            time.sleep(1)
            return_code = subprocess.call(["ssh", "-fND", port, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeychecking=no", "-o", "IdentitiesOnly=yes", "ec2-user@" + ip, "-i", "~/.ssh/" + args.keyname + ".pem"])
        print("Opened SOCKS proxy on port " + port + " for IP " + ip + ".")
        port = str(int(port) + 1)
    return 0


def port_valid(port):
    try:
        if int(port) > 1023 and int(port) < 49152:
            return True
        else:
            raise ValueError
    except ValueError:
        print("Port must be greater 1024 and less 49152.")
        return False


def port_busy(port):
    netstat = subprocess.check_output(["netstat", "-tulpen"], stderr=subprocess.DEVNULL).decode("utf-8")
    pattern_port = re.compile(r'(?<=127\.0\.0\.1:)' + port)
    netstat_port = re.findall(pattern_port, netstat)
    if netstat_port == []:
        return False
    else:
        return True


def ssh_dict():
    netstat = subprocess.check_output(["netstat", "-tulpen"], stderr=subprocess.DEVNULL).decode("utf-8")

    pattern_ssh = re.compile(r'.*127\.0\.0\.1.*ssh.*')
    netstat_ssh_list = re.findall(pattern_ssh, netstat)
    netstat_ssh = ''.join(netstat_ssh_list)

    #  pattern_port = re.compile(r'(?<=127\.0\.0\.1:)[0-9]+')
    #  ports = re.findall(pattern_port, netstat_ssh)
    #  print(ports)
    pattern_pid = re.compile(r'[0-9]+(?=/ssh)')
    pids = re.findall(pattern_pid, netstat_ssh)

    pattern_ip = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    pattern_port = re.compile(r'(?<=fND )[0-9]+')
    ips = {}
    for pid in pids:
        command = subprocess.check_output(["ps", "-p", pid, "-o", "args"], stderr=subprocess.DEVNULL).decode("utf-8")
        ip = re.findall(pattern_ip, command)
        if not ip == []:
            port = re.findall(pattern_port, command)
            ips[ip[0]] = [port[0]]
    return ips


def security_groups(args):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ["running"]}])
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    reservations = response["Reservations"]
    instanceids = [instance["InstanceId"] for reservation in reservations for instance in reservation["Instances"]]

    GROUPIDS = set()
    for instanceid in instanceids:
        response = ec2.describe_instance_attribute(Attribute='groupSet', DryRun=args.dryrun, InstanceId=instanceid)
        groupid = response["Groups"][0]["GroupId"]
        GROUPIDS.add(groupid)

    return GROUPIDS


def authorize_security_groups(args):
    # Authorize Security groups for connecting via port 22 from args.cidr
    ec2 = boto3.client('ec2')
    # logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    GROUPIDS = security_groups(args)
    print("Authorize Security Groups: Open port 22 for " + args.cidr)
    for groupid in GROUPIDS:
        try:
            ec2.authorize_security_group_ingress(CidrIp=args.cidr, GroupId=groupid, IpProtocol="TCP", FromPort=22, ToPort=22, DryRun=args.dryrun)
        except botocore.exceptions.ClientError as e:
            print(e)
            pass


def main(args, loglevel):
    logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
    if args.command == "stop":
        stop(args, loglevel, DRYRUN=args.dryrun)
    elif args.command == "start":
        if port_valid(args.port):
            start(args, loglevel, DRYRUN=args.dryrun)
    elif args.command == "ssh":
        ssh_up(args)
    else:
        status(args, loglevel)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Runs EC2 instances and opens SSH tunnel to it.",
        # epilog="As an alternative to the commandline, params can be placed in a file, one per line, and specified on the commandline like '%(prog)s @params.conf'.",
        fromfile_prefix_chars='@')
    parser.add_argument(
        "command",
        help="pass command to the program: start, stop, status, ssh",
        metavar="COMMAND")
    parser.add_argument(
        "-c",
        dest="number",
        help="number of instances to be ran (default: 1)",
        default=1,
        action="store")
    parser.add_argument(
        "-k",
        "--keyname",
        dest="keyname",
        help="SSH Key-Name",
        action="store")
    parser.add_argument(
        "-t",
        "--instancetype",
        dest="instancetype",
        help="EC2 Instance Type (default: t2.micro)",
        default="t2.micro",
        action="store")
    parser.add_argument(
        "-i",
        "--imageid",
        dest="imageid",
        help="AWS ImageId (default: ami-08935252a36e25f85)",
        default="ami-08935252a36e25f85",
        action="store")
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        help="Port for SOCKS Proxy. When more than one instance being launched, port will be incremented. (default: 9000)",
        default="9000",
        action="store")
    parser.add_argument(
        "-s",
        "--cidr",
        dest="cidr",
        help="IPv4 address range in CIDR fromat from which to allow connections to port 22.",
        default="0.0.0.0/0",
        action="store")
    parser.add_argument(
        "-v",
        "--verbose",
        help="increase output verbosity",
        action="store_true")
    parser.add_argument(
        "--dryrun",
        help="dry run API calls",
        action="store_true")
    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

main(args, loglevel)
