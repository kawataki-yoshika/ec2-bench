import boto3
import time
import json
import argparse
import sys
import uuid
import re
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_arguments():
    parser = argparse.ArgumentParser(description="Run performance tests on EC2 instances")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--vpc-id", required=True, help="VPC ID for the instance")
    parser.add_argument("--security-group", help="Security group ID (optional)")
    parser.add_argument("--instance-profile", help="IAM instance profile name (optional)")
    parser.add_argument("--instance-types", required=True, nargs='+', help="List of EC2 instance types")
    parser.add_argument("--scripts", nargs='+', help="List of additional scripts to run")
    return parser.parse_args()

def create_clients(region):
    return (
        boto3.client('ec2', region_name=region),
        boto3.client('ssm', region_name=region),
        boto3.client('iam')
    )

def get_vpc_cidr(ec2, vpc_id):
    response = ec2.describe_vpcs(VpcIds=[vpc_id])
    return response['Vpcs'][0]['CidrBlock']

def get_or_create_security_group(ec2, vpc_id):
    if args.security_group:
        return args.security_group

    vpc_cidr = get_vpc_cidr(ec2, vpc_id)
    group_name = f"temp-ec2-perf-test-{uuid.uuid4()}"
    print(f"Creating temporary security group: {group_name}")
    
    response = ec2.create_security_group(
        GroupName=group_name,
        Description="Temporary group for EC2 performance testing",
        VpcId=vpc_id
    )
    group_id = response['GroupId']
    
    # Wait for the security group to be available
    ec2.get_waiter('security_group_exists').wait(GroupIds=[group_id])
    
    # Add inbound rule for port 443 from VPC CIDR
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': vpc_cidr}]
            }
        ]
    )
    
    print(f"Created security group: {group_id}")
    return group_id

def create_temporary_instance_profile():
    iam = boto3.client('iam')
    role_name = f"temp-ec2-perf-test-role-{uuid.uuid4()}"
    instance_profile_name = f"temp-ec2-perf-test-profile-{uuid.uuid4()}"

    # Create IAM role
    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=assume_role_policy_document
    )

    # Attach AmazonSSMManagedInstanceCore policy
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    )

    # Create instance profile and add role to it
    iam.create_instance_profile(InstanceProfileName=instance_profile_name)
    iam.add_role_to_instance_profile(
        InstanceProfileName=instance_profile_name,
        RoleName=role_name
    )

    # Wait for the instance profile to be ready
    waiter = iam.get_waiter('instance_profile_exists')
    waiter.wait(InstanceProfileName=instance_profile_name)

    print(f"Created temporary instance profile: {instance_profile_name}")
    return instance_profile_name, role_name

def cleanup_temporary_instance_profile(instance_profile_name, role_name):
    iam = boto3.client('iam')

    # Remove role from instance profile
    iam.remove_role_from_instance_profile(
        InstanceProfileName=instance_profile_name,
        RoleName=role_name
    )

    # Delete instance profile
    iam.delete_instance_profile(InstanceProfileName=instance_profile_name)

    # Detach policy from role
    iam.detach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    )

    # Delete role
    iam.delete_role(RoleName=role_name)

    print(f"Cleaned up temporary instance profile and role")

def wait_for_instance_profile(ec2, ssm, iam, instance_profile_name, max_retries=20, delay=15):
    
    print(f"Waiting for instance profile {instance_profile_name} to be fully available...")
    
    ami_id = get_latest_amazon_linux_2_ami(ssm, args.region, 'x86_64')

    for attempt in range(max_retries):
        try:
            # Check if the instance profile exists in IAM
            iam.get_instance_profile(InstanceProfileName=instance_profile_name)
            
            # Try to use the instance profile in a dry run EC2 request
            try:
                ec2.run_instances(
                    DryRun=True,
                    MinCount=1,
                    MaxCount=1,
                    ImageId=ami_id,  # This is a dummy AMI ID
                    InstanceType='t2.micro',
                    IamInstanceProfile={'Name': instance_profile_name}
                )
            except ClientError as e:
                if 'DryRunOperation' not in str(e):
                    # If the error is not about DryRun, it means the instance profile is not yet available
                    raise Exception("Instance profile is not yet available for EC2")
            
            # If we get here without an exception, the profile is available
            print(f"Instance profile {instance_profile_name} is now fully available")
            return True
        
        except Exception as e:
            print(f"Waiting for instance profile to be available... (Attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)

    print(f"Timeout waiting for instance profile {instance_profile_name}")
    return False

def get_instance_architecture(instance_type):
    # インスタンスファミリーを取得（例: 't4g' from 't4g.micro'）
    instance_family = instance_type.split('.')[0]
    
    # 数値の直後に 'g' がある場合は ARM
    if re.match(r'^[a-z]+\d+g', instance_family):
        return 'arm64'
    
    # Mac インスタンス（現在は x86_64 だが、将来 ARM になる可能性がある）
    if instance_family.startswith('mac'):
        raise NotImplementedError("Mac instances are not supported")
    
    # デフォルトは x86_64
    return 'x86_64'

def get_latest_amazon_linux_2_ami(ssm, region, architecture):
    if architecture == 'arm64':
        param_name = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64'
    else:
        param_name = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
    
    response = ssm.get_parameter(Name=param_name)
    return response['Parameter']['Value']
    
def get_valid_subnet(ec2, instance_type, vpc_id):
    
    # リージョン取得
    region = ec2.meta.region_name

    # インスタンスタイプが利用可能なアベイラビリティゾーンを取得
    response = ec2.describe_instance_type_offerings(
        LocationType='availability-zone',
        Filters=[
            {
                'Name': 'instance-type',
                'Values': [instance_type]
            }
        ]
    )
    
    available_azs = [offering['Location'] for offering in response['InstanceTypeOfferings']]
    
    if not available_azs:
        raise ValueError(f"インスタンスタイプ {instance_type} が利用可能なアベイラビリティゾーンが見つかりません。")
    
    # VPC内の全サブネットを取得
    response = ec2.describe_subnets(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }
        ]
    )
    
    # インターネットに接続可能で、利用可能なアベイラビリティゾーンにあるサブネットをフィルタリング
    valid_subnets = []
    for subnet in response['Subnets']:
        if subnet['AvailabilityZone'] not in available_azs:
            continue
        
        # サブネットのルートテーブルを取得
        route_table_response = ec2.describe_route_tables(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [subnet['SubnetId']]
                }
            ]
        )
        
        # ルートテーブルが関連付けられていない場合、VPCのメインルートテーブルを取得
        if not route_table_response['RouteTables']:
            route_table_response = ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },
                    {
                        'Name': 'association.main',
                        'Values': ['true']
                    }
                ]
            )
        
        # インターネットゲートウェイまたはNAT Gatewayへのルートがあるか確認
        for route_table in route_table_response['RouteTables']:
            for route in route_table['Routes']:
                if route.get('GatewayId', '').startswith('igw-') or route.get('NatGatewayId', '').startswith('nat-'):
                    valid_subnets.append(subnet)
                    break
            if subnet in valid_subnets:
                break
    
    if not valid_subnets:
        raise ValueError(f"VPC {vpc_id} 内に、インスタンスタイプ {instance_type} が利用可能でインターネットに接続可能なサブネットが見つかりません。")

    # 最初の有効なサブネットを返す
    return valid_subnets[0]['SubnetId'], valid_subnets[0]['AvailabilityZone']

def launch_ec2_spot_instance(ec2, instance_type, security_group, instance_profile, ami_id, vpc_id):
    try:

        subnet_id, az = get_valid_subnet(ec2, instance_type, vpc_id)
        print(f"Using subnet: {subnet_id}({az}) for {instance_type}")

        launch_specification = {
            'ImageId': ami_id,
            'InstanceType': instance_type,
            'SecurityGroupIds': [security_group],
            'SubnetId': subnet_id,
            'IamInstanceProfile': {'Name': instance_profile},
        }

        spot_params = {
            'InstanceCount': 1,
            'Type': 'one-time',
            'LaunchSpecification': launch_specification
        }

        response = ec2.request_spot_instances(**spot_params)
        request_id = response['SpotInstanceRequests'][0]['SpotInstanceRequestId']
        print(f"Spot instance request submitted: {request_id}")

        # Wait for the spot instance request to be fulfilled
        waiter = ec2.get_waiter('spot_instance_request_fulfilled')
        waiter.wait(SpotInstanceRequestIds=[request_id])

        # Get the instance ID
        spot_request = ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[request_id])
        instance_id = spot_request['SpotInstanceRequests'][0]['InstanceId']
        print(f"Spot instance launched: {instance_id}")

        return instance_id
    except Exception as e:
        print(f"Error launching spot instance: {instance_type}: {str(e)}")
        return None

def wait_for_instance_ssm_ready(ssm, instance_id, max_retries=20, delay=15):
    print(f"Waiting for instance {instance_id} to be ready for SSM connections...")
    for attempt in range(max_retries):
        try:
            response = ssm.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )
            if response['InstanceInformationList']:
                print(f"Instance {instance_id} is now ready for SSM connections")
                return True
        except ClientError as e:
            print(f"Error checking SSM status: {e}")
        
        print(f"Instance not yet ready for SSM. Attempt {attempt + 1}/{max_retries}")
        time.sleep(delay)
    
    print(f"Timeout waiting for instance {instance_id} to be ready for SSM")
    return False

def wait_for_instance(ec2, ssm, instance_id):
    print(f"Waiting for instance {instance_id} to be running...")
    ec2.get_waiter('instance_running').wait(InstanceIds=[instance_id])
    print(f"Instance {instance_id} is now running")
    
    print(f"Waiting for instance {instance_id} to pass status checks...")
    ec2.get_waiter('instance_status_ok').wait(InstanceIds=[instance_id])
    print(f"Instance {instance_id} has passed all status checks")
    
    if not wait_for_instance_ssm_ready(ssm, instance_id):
        raise Exception(f"Instance {instance_id} did not become ready for SSM connections in time")

def run_command(ssm, instance_id, command):
    print(f"Running command on instance {instance_id}: {command}")
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': [command]}
    )
    command_id = response['Command']['CommandId']
    
    # Wait for the command to complete
    for _ in range(20):  # Timeout after 20 * 15 seconds
        time.sleep(15)
        result = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        if result['Status'] in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
            print(f"Command completed with status: {result['Status']}")
            return result['StandardOutputContent'], result['StandardErrorContent']
    
    raise Exception("Timeout waiting for command to complete")

def get_instance_info(ec2, ssm, instance_id):
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance_type = response['Reservations'][0]['Instances'][0]['InstanceType']
    
    instance_type_info = ec2.describe_instance_types(InstanceTypes=[instance_type])['InstanceTypes'][0]
    
    core_count = instance_type_info['VCpuInfo']['DefaultVCpus']
    memory_size_mb = instance_type_info['MemoryInfo']['SizeInMiB']
    
    # CPU モデル情報の取得
    architecture = get_instance_architecture(instance_type)
    if architecture == 'arm64':
        cpu_info_command = "cat /proc/cpuinfo | grep 'CPU part' | uniq | awk '{print $4}'"
        stdout, _ = run_command(ssm, instance_id, cpu_info_command)
        cpu_model = f"AWS Graviton3 (CPU part: {stdout.strip()})"
    else:
        cpu_info_command = "cat /proc/cpuinfo | grep 'model name' | uniq | awk -F': ' '{print $2}'"
        stdout, _ = run_command(ssm, instance_id, cpu_info_command)
        cpu_model = stdout.strip()
    
    return {
        'core_count': core_count,
        'memory_size_mb': memory_size_mb,
        'cpu_model': cpu_model
    }

def install_sysbench(ssm, instance_id):
    print("Installing sysbench...")
    install_commands = [
        "sudo dnf -y install make automake libtool pkgconfig libaio-devel openssl-devel git",
        "cd /tmp && git clone https://github.com/akopytov/sysbench.git -b 1.0.20 && cd sysbench && ./autogen.sh && ./configure --without-mysql --without-pgsql && make && sudo make install"
    ]
    results = []
    for command in install_commands:
        stdout, stderr = run_command(ssm, instance_id, command)
        results.append({"stdout": stdout, "stderr": stderr})
        if stderr:
            print(f"Warning during sysbench installation step: {stderr}")
    print("Sysbench installation completed.")
    return results

def run_performance_tests(ec2, ssm, instance_id, custom_scripts):
    results = {}
    
    # Install sysbench
    install_stdout, install_stderr = install_sysbench(ssm, instance_id)
    print(f'{install_stdout}')
    if install_stderr:
        print(f'{install_stderr}')

    # Get instance info
    instance_info = get_instance_info(ec2, ssm, instance_id)
    core_count = instance_info['core_count']
    memory_size_mb = instance_info['memory_size_mb']
    cpu_model = instance_info['cpu_model']
    
    print(f"Instance has {core_count} CPU cores, {memory_size_mb} MB of memory")
    print(f"CPU Model: {cpu_model}")

    # Add CPU model to results
    results['instance_info'] = {
        'core_count': core_count,
        'memory_size_mb': memory_size_mb,
        'cpu_model': cpu_model
    }
    
    # Single-core CPU test
    single_core_command = "sysbench cpu --cpu-max-prime=20000 --threads=1 run"
    print(f"Running Single-core CPU test: {single_core_command}")
    results['cpu_single_core'] = run_command(ssm, instance_id, single_core_command)
    
    # Multi-core CPU test (using all cores)
    multi_core_command = f"sysbench cpu --cpu-max-prime=20000 --threads={core_count} run"
    print(f"Running Multi-core CPU test: {multi_core_command}")
    results['cpu_multi_core'] = run_command(ssm, instance_id, multi_core_command)

    # Memory test
    # Use 80% of total memory for the test, but cap it at 100GB to avoid excessive test duration
    memory_test_size = min(int(memory_size_mb * 0.8), 100 * 1024)
    memory_command = f"sysbench memory --memory-block-size=1M --memory-total-size={memory_test_size}M run"
    print(f"Running Memory test: {memory_command}")
    results['memory'] = run_command(ssm, instance_id, memory_command)

    # File I/O test
    fileio_command = "sysbench fileio --file-test-mode=rndrw prepare && sysbench fileio --file-test-mode=rndrw run && sysbench fileio --file-test-mode=rndrw cleanup"
    print(f"Running File I/O test: {fileio_command}")
    results['fileio'] = run_command(ssm, instance_id, fileio_command)

    # Run custom scripts if provided
    if custom_scripts:
        for script in custom_scripts:
            print(f"Running custom script: {script}")
            results[f'custom_{custom_scripts.index(script)}'] = run_command(ssm, instance_id, f"bash -c '{script}'")

    return results

def stop_ec2_instance(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    print(f"Stopping instance {instance_id}")

def wait_for_eni_release(ec2, security_group_id, max_retries=20, delay=15):
    for attempt in range(max_retries):
        try:
            response = ec2.describe_network_interfaces(
                Filters=[
                    {'Name': 'group-id', 'Values': [security_group_id]}
                ]
            )
            if not response['NetworkInterfaces']:
                print(f"All ENIs associated with security group {security_group_id} have been released")
                return True
            print(f"Waiting for ENIs to be released... (Attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
        except ClientError as e:
            print(f"Error checking ENIs: {e}")
            return False
    print(f"Timeout waiting for ENIs associated with security group {security_group_id} to be released")
    return False

def cleanup_resources(ec2, security_group_id, args):
    if not args.security_group:
        print(f"Waiting for ENIs to be released before deleting security group: {security_group_id}")
        if wait_for_eni_release(ec2, security_group_id):
            try:
                print(f"Deleting temporary security group: {security_group_id}")
                ec2.delete_security_group(GroupId=security_group_id)
                print(f"Successfully deleted security group: {security_group_id}")
            except ClientError as e:
                print(f"Failed to delete security group {security_group_id}: {e}")
        else:
            print(f"Unable to delete security group {security_group_id} due to lingering ENIs")

def run_benchmark(ec2, ssm, instance_type, security_group_id, instance_profile, vpc_id, scripts):
    architecture = get_instance_architecture(instance_type)
    print(f"Detected architecture for {instance_type}: {architecture}")
    
    ami_id = get_latest_amazon_linux_2_ami(ssm, ec2.meta.region_name, architecture)
    print(f"Using AMI: {ami_id} for {instance_type}")
    
    instance_id = launch_ec2_spot_instance(ec2, instance_type, security_group_id, instance_profile, ami_id, vpc_id)
    wait_for_instance(ec2, ssm, instance_id)
    
    try:
        results = run_performance_tests(ec2, ssm, instance_id, scripts)
        return {instance_type: results}
    finally:
        stop_ec2_instance(ec2, instance_id)

def main(args):
    ec2, ssm, iam = create_clients(args.region)

    security_group_id = get_or_create_security_group(ec2, args.vpc_id)
    
    if not args.instance_profile:
        instance_profile, role_name = create_temporary_instance_profile()
        if not wait_for_instance_profile(ec2, ssm, iam, instance_profile):
            print("Failed to create instance profile. Exiting.")
            return
    else:
        instance_profile = args.instance_profile
        role_name = None

    results = {}
    try:
        with ThreadPoolExecutor(max_workers=len(args.instance_types)) as executor:
            future_to_instance = {executor.submit(run_benchmark, ec2, ssm, instance_type, security_group_id, instance_profile, args.vpc_id, args.scripts): instance_type for instance_type in args.instance_types}
            for future in as_completed(future_to_instance):
                instance_type = future_to_instance[future]
                try:
                    result = future.result()
                    if result:
                        results.update(result)
                except Exception as exc:
                    print(f'{instance_type} generated an exception: {exc}')
    finally:
        cleanup_resources(ec2, security_group_id, args)
        if role_name:
            cleanup_temporary_instance_profile(instance_profile, role_name)

    # タイムスタンプ取得(YYYYMMDDHHMMSS)
    timestamp = time.strftime('%Y%m%d%H%M%S', time.localtime())
    output_file = f'dist/performance_results.{timestamp}.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Performance test results for all instance types have been saved to '{output_file}'")

if __name__ == "__main__":
    args = parse_arguments()
    main(args)