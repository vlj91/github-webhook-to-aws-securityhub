# `github-webhook-to-aws-securityhub`

* AWS Lambda Function sat behind API Gateway
* Point GitHub Organization or Repository at the gateway
* Handles vulnerability finding create and resolve events
* Imports into AWS SecurityHub using the ASFF syntax
* Looks up extra info about the vulnerability using RedHat CVE DB
