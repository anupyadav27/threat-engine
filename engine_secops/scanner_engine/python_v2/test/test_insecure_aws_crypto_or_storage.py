# Noncompliant: weak hashing algorithms
import hashlib
md5 = hashlib.md5('test'.encode('utf-8')).hexdigest()  # should trigger
sha1 = hashlib.sha1('test'.encode('utf-8')).hexdigest()  # should trigger

# Compliant: secure hashing
sha256 = hashlib.sha256('test'.encode('utf-8')).hexdigest()

# Noncompliant: SQS queue without encryption
import boto3
client = boto3.client('sqs')
queue = client.create_queue(QueueName='myqueue', Attributes={'EncryptionType': 'NONE'})  # should trigger

# Compliant: SQS queue with encryption
queue2 = client.create_queue(QueueName='myqueue', Attributes={'EncryptionType': 'AES256'})

# Noncompliant: SNS topic without KMS
sns = boto3.client('sns')
sns.create_topic(TopicArn='arn:aws:sns:us-west-2:123456789012:MyTopic', TopicName='MyTopic')  # should trigger

# Compliant: SNS topic with KMS
sns.create_topic(TopicArn='arn:aws:sns:us-west-2:123456789012:MyEncryptedTopic', TopicName='MyEncryptedTopic', KmsMasterKeyId='arn:aws:kms:us-west-2:123456789012:key/MyEncryptionKey')

# Noncompliant: SageMaker notebook without encryption
boto3.client('sagemaker-runtime').create_notebook_instance(NotebookInstanceName='test-instance', IamRoleArn='arn:aws:iam::123456789012:role/my-iam-for-sagemaker')  # should trigger

# Compliant: SageMaker notebook with encryption
boto3.client('sagemaker-runtime').create_notebook_instance(NotebookInstanceName='test-instance', IamRoleArn='arn:aws:iam::123456789012:role/my-iam-for-sagemaker', EncryptionOptions={'EncryptionInTransit': {'Enabled': True}, 'EncryptionAtRest': {'Enabled': True}})
