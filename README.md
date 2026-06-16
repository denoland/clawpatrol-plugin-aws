# clawpatrol-plugin-aws

An external [clawpatrol](https://github.com/denoland/clawpatrol) plugin
that gates calls to the **AWS APIs**. It terminates the agent's TLS,
parses each request into an `aws` facet so rules can match AWS
operations by name, signs the request with **SigV4** using a per-account
credential, and forwards it to AWS through the gateway's brokered dial.

## What it provides

- **Facet `aws`** — the rule-matching vocabulary: `aws.service`,
  `aws.action`, `aws.region`, `aws.resource`, `aws.method`.
- **Endpoint `aws_api`** — terminates TLS, evaluates the parsed action,
  SigV4-signs, and brokered-dials `*.amazonaws.com:443`. It runs with
  **no network of its own** (`network = none`); every upstream
  connection is the gateway's audited brokered dial.
- **Credential `aws_account`** — one AWS account's signing identity
  (access key id / secret access key / optional session token). Multiple
  accounts are multiple credential instances.

## Example

```hcl
plugin "aws" {
  source  = "github.com/denoland/clawpatrol-plugin-aws"
  version = "~> 0.1"
}

credential "aws_account" "prod" {
  region = "us-east-1"
}

endpoint "aws_api" "aws-prod" {
  hosts      = ["*.amazonaws.com"]
  credential = aws_account.prod
}

# A second account is just another credential + endpoint instance.
credential "aws_account" "sandbox" { region = "us-west-2" }
endpoint "aws_api" "aws-sandbox" {
  hosts      = ["*.amazonaws.com"]
  credential = aws_account.sandbox
}

rule "no destructive s3" {
  endpoints = [aws_api.aws-prod]
  match     = aws.service == "s3" && aws.action.startsWith("Delete")
  action    = "deny"
}
```

The access key id and secret access key are entered on the dashboard
(the credential's secret slots); the agent never sees them — it talks
plaintext to the gateway, which signs and forwards.

## Action parsing

The operation name (`aws.action`) is derived from:

- `X-Amz-Target` for JSON-protocol services
  (`DynamoDB_20120810.PutItem` → `PutItem`),
- the `Action` query/body parameter for query-protocol services
  (`DescribeInstances`),
- otherwise `METHOD path` (e.g. S3: `DELETE /bucket/key`).

## Status

Early. The endpoint, facet, credential, SigV4 signing, and action
parsing for the common protocols work. Not yet covered: streaming /
chunked request bodies, `s3` virtual-host-style buckets in the service
parse, and per-service action extraction beyond the three shapes above.
