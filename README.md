# How to deploy project with CloudFormation
To deploy with CloudFormation run the following function: `aws cloudformation create-stack --stack-name code-pipeline-project --template-body file://pipeline/cf-template.yml --capabilities CAPABILITY_NAMED_IAM --region ap-southeast-2`
