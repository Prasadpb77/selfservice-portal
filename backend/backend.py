from flask import Flask, render_template, request, jsonify
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__,template_folder='frontend')



def assume_role(account_number):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_number}:role/INSTANCE-START-STOP'
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    credentials = response['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

@app.route('/api/get_ec2_instances', methods=['POST'])
def get_ec2_instances():
    account_number = request.form['aws_account_number']
    region = request.form['aws_region']
    session = assume_role(account_number)
    ec2_client = session.client('ec2', region_name=region)
    try:
        response = ec2_client.describe_instances()
        instances = []
        response = ec2_client.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                status_checks = ec2_client.describe_instance_status(InstanceIds=[instance_id])['InstanceStatuses']
                if status_checks:
                    status_check = status_checks[0]['InstanceStatus']['Status']
                else:
                    status_check = 'Status checks not available'
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                instance_name = ''
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                instances.append({
                    'InstanceId': instance_id,
                    'Name': instance_name,
                    'State': state.capitalize(),
                    'StatusCheck': status_check.capitalize(),
                    'Region': region,
                    'PrivateIpAddress': private_ip
                })
        return jsonify({'instances': instances})
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop_ec2_instance', methods=['POST'])
def stop_ec2_instance():
    account_number = request.form['account_number']
    region = request.form['region']
    instance_id = request.form['instance_id']
    session = assume_role(account_number)
    ec2_client = session.client('ec2', region_name=region)

    try:
        ec2_client.stop_instances(InstanceIds=[instance_id])
        return jsonify({'message': f'Instance {instance_id} is stopping.'})
    except ClientError as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/start_ec2_instance', methods=['POST'])
def start_ec2_instance():
    account_number = request.form['account_number']
    region = request.form['region']
    instance_id = request.form['instance_id']
    session = assume_role(account_number)
    ec2_client = session.client('ec2', region_name=region)

    try:
        ec2_client.start_instances(InstanceIds=[instance_id])
        return jsonify({'message': f'Instance {instance_id} is starting.'})
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)