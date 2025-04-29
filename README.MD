# 🌐 Website Protocol & SSL Certificate Checker

## 📜 Description
A **serverless Python application** that checks whether a provided website URL uses **HTTP** or **HTTPS**. If the site uses HTTPS, the app retrieves the SSL certificate’s expiration date. The results are sent as an **email notification** using **AWS SNS**.

This tool is ideal for:
- Basic website security monitoring
- SSL certificate management

---

## 🛠️ Prerequisites
Before you begin, ensure you have the following:
- ✅ **AWS Account** with permissions for Lambda and SNS
- ✅ **Python 3.x** (Recommended: Python 3.11)
- ✅ **AWS CLI** (Optional, for deployment)
- ✅ **boto3 library** (Included in AWS Lambda Python runtimes)
- ✅ An **SNS topic** with an email subscription

---

## 🚀 Installation

### 1️⃣ Create an SNS Topic
1. Go to the **AWS SNS Console**.
2. Create a new topic (e.g., `website-checker-alerts`).
3. Add your email as a subscriber and confirm the subscription.

### 2️⃣ Set Up the Lambda Function
1. Go to the **AWS Lambda Console**.
2. Create a new function using the **Python 3.x runtime**.
3. Add the code from this repository (`lambda_function.py`).
4. Add an **environment variable**:
   - **Key**: `SNS_TOPIC_ARN`
   - **Value**: Your SNS topic ARN

### 3️⃣ IAM Permissions
Ensure your Lambda execution role includes permission to publish to your SNS topic. Add the following policy:

```json
{
  "Effect": "Allow",
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:<region>:<account-id>:<topicname>"
}
```

---

## Usage
Invoke the Lambda function with an event containing a URL, for example:
{
  "url": "https://example.com"
}

The function will:
oCheck if the site uses HTTP or HTTPS.
oIf HTTPS, retrieve the SSL certificate expiration date.
oSend a notification email with the results.

## Code Example
```python
import ssl
import socket
import boto3
import os
from urllib.parse import urlparse
from datetime import datetime

sns_client = boto3.client('sns')

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

    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
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

---

## Notes
Make sure your Lambda function has outbound internet access (for example, not in a private VPC without a NAT gateway) to check external websites.
The SSL certificate expiration check only works for HTTPS URLs.
You can modify the notification message or add more logic as needed.

## License
This project is provided for educational and informational purposes. Use responsibly and in accordance with all applicable laws and AWS best practices.

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss your ideas.

