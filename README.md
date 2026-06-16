# clawpatrol-plugin-aws

An external [clawpatrol](https://github.com/denoland/clawpatrol) plugin
that gates calls to the **AWS APIs across many accounts**. It terminates
the agent's TLS, parses each request into an `aws` facet so rules can
match AWS operations by name, selects the target account from the
request, **assumes a per-account role** with a single base key, re-signs
with SigV4, and forwards to AWS through the gateway's brokered dial.

## What it provides

- **Facet `aws`** — the rule vocabulary: `aws.service`, `aws.action`,
  `aws.account`, `aws.region`, `aws.resource`, `aws.method`.
- **Endpoint `aws_api`** — terminates TLS, evaluates the parsed action,
  assumes the per-account role, re-signs, and brokered-dials AWS. Runs
  with **no network of its own** (`network = none`); both the API call
  and the STS `AssumeRole` go through the gateway's audited brokered dial.
- **Credential `aws_account`** — the single **base key** (access key id /
  secret access key / optional session token) used to assume each
  account's role.

## Multi-account model

One base IAM key (in a hub account) plus a role of the **same name** in
each member account that the base key is allowed to assume. The agent
picks the account by the access key id in its per-account AWS profile —
the operator sets that to **encode the 12-digit account id**, e.g.

```ini
# ~/.aws/credentials on the agent
[denoland]
aws_access_key_id     = AKIA035475582903XXXX   # encodes account 035475582903
aws_secret_access_key = placeholder            # ignored; the gateway re-signs

[metrics]
aws_access_key_id     = AKIA058264286601XXXX
aws_secret_access_key = placeholder
```

The agent's secret can be any placeholder; the gateway strips the agent's
SigV4 signature and re-signs with the assumed-role credentials. The
plugin derives the target account from the access key id, assumes
`arn:aws:iam::<account>:role/<role>`, and signs with the temporary
credentials (cached per account until shortly before expiry).

## Example

```hcl
plugin "aws" {
  source  = "github.com/denoland/clawpatrol-plugin-aws"
  version = "~> 0.1"
}

credential "aws_account" "base" {}   # base key entered on the dashboard

endpoint "aws_api" "avocet2" {
  hosts      = ["*.amazonaws.com"]
  role       = "clawpatrol-gateway"  # role assumed in each account
  region     = "us-east-1"
  credential = aws_account.base
}

# Broad reads allowed; mutations need human approval; secrets denied.
rule "reads ok" {
  endpoints = [aws_api.avocet2]
  match     = aws.action.startsWith("Get") || aws.action.startsWith("List") || aws.action.startsWith("Describe")
  action    = "allow"
}

rule "mutations need approval" {
  endpoints = [aws_api.avocet2]
  match     = !(aws.action.startsWith("Get") || aws.action.startsWith("List") || aws.action.startsWith("Describe"))
  action    = "approve"
  approvers = [human.oncall]
}
```

## Action parsing

`aws.action` is derived from `X-Amz-Target` for JSON-protocol services
(`DynamoDB_20120810.PutItem` → `PutItem`), the `Action` parameter for
query-protocol services (`DescribeInstances`), otherwise `METHOD path`
(S3: `DELETE /bucket/key`).

## Status

Early. Endpoint / facet / credential, account selection, STS AssumeRole
over the brokered dial (with credential caching), SigV4 re-signing, and
action parsing for the common protocols work and are unit-tested. Not
yet verified end to end against a live gateway + real AWS. Not yet
covered: chunked/streaming request bodies, S3 virtual-host-style buckets
in the service parse, and the regional-vs-global STS endpoint choice
beyond `us-east-1`.
