# ec2-proxies
Use EC2 instances as SOCKS proxies.

This script uses default AWS credentials to run a specified number of EC2 Instances and opens SSH tunnels to the instances.

As default t2.micro instances will be ran since these are included in the free tier of AWS.

An SSH keyset must be created in the AWS management console and saved locally in `~/.ssh`. The name of the SSH key must be refered by the argumen `-k`. All other arguments are optional.

`aws-proxies.py start -k name-ssh` starts one t2.micro instance, connects to it via SSH and opens a SOCKS proxy on Port 9000.

`aws-proxies.py status` shows all running EC2 Instances, its State, InstanceID, PublicIP, GroupID and SOCKS proxy port.

`aws-proxies.py ssh -k name-ssh` connects via SSH and opens a SOCKS proxy to all EC2 instances, to which no SSH tunnel exists yet.

`aws-proxies.py stop` terminates all running EC2 instances - also those not started with this script!

```
$ aws-proxies.py -h
usage: aws-proxies.py [-h] [-c NUMBER] [-k KEYNAME] [-t INSTANCETYPE]
                      [-i IMAGEID] [-p PORT] [-s CIDR] [-v] [--dryrun]
                      COMMAND

Runs EC2 instances and opens SSH tunnel to it.

positional arguments:
  COMMAND               pass command to the program: start, stop, status, ssh

optional arguments:
  -h, --help            show this help message and exit
  -k KEYNAME, --keyname KEYNAME
                        SSH Key-Name
  -c NUMBER             number of instances to be ran (default: 1)
  -t INSTANCETYPE, --instancetype INSTANCETYPE
                        EC2 Instance Type (default: t2.micro)
  -i IMAGEID, --imageid IMAGEID
                        AWS ImageId (default: ami-08935252a36e25f85)
  -p PORT, --port PORT  Port for SOCKS Proxy. When more than one instance
                        being launched, port will be incremented. (default:
                        9000)
  -s CIDR, --cidr CIDR  IPv4 address range in CIDR fromat from which to allow
                        connections to port 22. (Default: 0.0.0.0)
  -v, --verbose         increase output verbosity
  --dryrun              dry run API calls
  ```
