#!/usr/bin/python
'''Start an ec2 node, run a remote command, then shutdown'''

import argparse
import socket
import sys
import time

import boto3
import paramiko

def parse_arguments():
    '''Parse CLI options'''
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--id", type=str, help="ec2 Instance Id", required=True)
    parser.add_argument("-n", "--name", type=str, help="ec2 Instance Hostname", required=True)
    parser.add_argument("-u", "--user", type=str, help="ec2 Login Username", required=True)
    parser.add_argument("-k", "--keyfile", type=str, help="RSA keyfile path", required=True)
    parser.add_argument("-p", "--profile", type=str, help="AWS Profile", required=False)
    parser.add_argument("-r", "--role", type=str, help="IAM Role", required=False)
    parser.add_argument("-c", "--commands", nargs='+', help="Remote command(s)", required=True)
    parser.add_argument("-t", "--timeout", type=int, help="Command timeout in seconds",
                        required=False, default=None)
    args = parser.parse_args()
    return args


def assume_role(session, role):
    '''Assume a role in AWS'''
    sts_client = session.client('sts')
    assumed_role = sts_client.assume_role(
        RoleArn=role,
        RoleSessionName="RemoteRoleSession"
    )
    credentials = assumed_role['Credentials']
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    return ec2_client


class TimeoutError(Exception):
    '''Raised when a command runs too long'''
    pass


class RemoteControl(object):
    '''Control ec2 instance state'''

    def __init__(self, ec2id, hostname, profile, role):
        if profile:
            session = boto3.Session(profile_name=profile)
        else:
            session = boto3.Session()
        if role:
            client = assume_role(session, role)
        else:
            client = session.client('ec2')
        self.client = client
        self.ec2id = ec2id
        self.hostname = hostname

    def start_instance(self):
        '''Start ec2 instance'''
        response = self.client.start_instances(
            InstanceIds=[
                self.ec2id,
            ]
        )
        try:
            for instance in response['StartingInstances']:
                if instance['InstanceId'] == self.ec2id:
                    return True
            return False
        except KeyError:
            return False

    def stop_instance(self):
        '''Stop ec2 instance'''
        response = self.client.stop_instances(
            InstanceIds=[
                self.ec2id,
            ]
        )
        try:
            for instance in response['StoppingInstances']:
                if instance['InstanceId'] == self.ec2id:
                    return True
            return False
        except KeyError:
            return False

    def wait_for_ssh(self):
        '''Wait for ec2 ssh to open'''
        while True:
            try:
                socket.create_connection((self.hostname, 22), 1)
                return
            except socket.error:
                time.sleep(2)


class RemoteNode(object):
    '''Execute commands on remote node'''

    def __init__(self, hostname, username, keyfile):
        self.hostname = hostname
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sshkey = paramiko.RSAKey.from_private_key_file(keyfile)
        self.ssh.connect(hostname=self.hostname, username=username, pkey=self.sshkey)

    def execute(self, command, timeout=None):
        '''Run a remote command and return the exit code and output'''
        start = time.time()
        _, stdout, stderr = self.ssh.exec_command(command)
        if timeout:
            while time.time() < start + timeout:
                if stdout.channel.exit_status_ready():
                    break
                time.sleep(1)
            else:
                raise TimeoutError('{} exceeded timeout of {}'.format(command, timeout))
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, stdout, stderr

    def close(self):
        '''Close the SSH connection'''
        self.ssh.close()
        return


def main():
    '''Node control and remote execution'''
    args = parse_arguments()
    ec2id = args.id
    hostname = args.name
    username = args.username
    keyfile = args.keyfile
    profile = args.profile
    role = args.role
    commands = args.commands
    timeout = args.timeout
    ec2_control = RemoteControl(ec2id, hostname, profile, role)
    # Start instance
    print "Starting ec2 instance {}".format(ec2id)
    start_req = ec2_control.start_instance()
    if not start_req:
        print "ERROR: Failed to start instance {}".format(ec2id)
        sys.exit(1)
    print "Waiting for SSH ..."
    ec2_control.wait_for_ssh()
    # Execute commands
    ec2_node = RemoteNode(hostname, username, keyfile)
    err_count = 0
    for command in commands:
        print "Executing remote command '{}' {}".format(command, timeout)
        try:
            exit_status, stdout, stderr = ec2_node.execute(command, timeout=timeout)
            if exit_status != 0:
                print "ERROR: Non-zero exit on '{}'".format(command)
                print stderr.read()
                err_count += 1
            else:
                print stdout.read()
        except TimeoutError, err:
            print "ERROR: {}".format(err)
            err_count += 1
    ec2_node.close()
    print "Finished all command requests"
    # Stop instance
    print "Stopping ec2 instance {}".format(ec2id)
    stop_req = ec2_control.stop_instance()
    if not stop_req:
        print "ERROR: Failed to stop instance {}".format(ec2id)
        sys.exit(1)
    # Eval command exits
    if err_count != 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
