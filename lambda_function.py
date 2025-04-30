import os
import boto3
import ssl
import socket  
from urllib.parse import urlparse
from datetime import datetime

sns_client = boto3.client('sns')  # consistent variable name

def get_cert_expiration_date(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            expire_date_str = cert.get('notAfter')
            if not expire_date_str:
                raise ValueError("Certificate does not have 'notAfter' field")
            expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
            return expire_date

def lambda_handler(event, context):
    url = event.get('url')
    if not url:
        return {
            'statusCode': 400,
            'body': 'Please provide a URL in the "url" field of the event.'
        }

    parsed_url = urlparse(url)
    protocol = parsed_url.scheme

    if protocol == "https":
        result = "The website uses HTTPS (secure)."
        try:
            expire_date = get_cert_expiration_date(parsed_url.hostname)
            expire_date_str = expire_date.strftime('%Y-%m-%d %H:%M:%S')
            result += f" Certificate expires on {expire_date_str}."
        except Exception as e:
            expire_date_str = "Unknown"
            result += f" Could not retrieve certificate expiration date: {str(e)}"

    elif protocol == "http":
        result = "The website uses HTTP (not secure)."
        expire_date_str = None
    else:
        result = "Unknown protocol."
        expire_date_str = None

    sns_topic_arn = os.environ.get('SNS_ARN')  
    if sns_topic_arn:
        message = f"URL checked: {url}\nProtocol: {protocol}\nCertificate Expiration Date: {expire_date_str}"
        try:
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject="Website Protocol and SSL Certificate Info",
                Message=message
            )
        except Exception as e:
            print(f"Error sending SNS notification: {e}")

    return {
        'statusCode': 200,
        'body': result
    }
