# Warning
This is a backup version of our codebase in AWS CodeCommit, credentials are removed in the for security reasons and are marked as 'xxxxx'. This tool has to be setup on AWS environment with the correct crendentials to run. For any further issue, please contact Marco

# How to deploy project with CloudFormation
To deploy with CloudFormation run the following function: `aws cloudformation create-stack --stack-name code-pipeline-project --template-body file://pipeline/cf-template.yml --capabilities CAPABILITY_NAMED_IAM --region ap-southeast-2`
