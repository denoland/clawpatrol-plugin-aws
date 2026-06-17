# clawpatrol-plugin-aws

An external [clawpatrol](https://github.com/denoland/clawpatrol) plugin
that gates calls to the **AWS APIs across many accounts**. It terminates
the agent's TLS, parses each request into an `aws` facet so rules can
match AWS operations by name, selects the target account from the
request, **assumes a per-account role** with a single base key, re-signs
with SigV4, and forwards to AWS through the gateway's brokered dial.

## What it provides

- **Facet `aws`** — the rule vocabulary: `aws.service`, `aws.action`,
  `aws.iam_action`, `aws.account`, `aws.account_name`, `aws.region`,
  `aws.resource`, `aws.method`.
  - `aws.action` is the **API operation name** (CloudTrail `eventName`),
    e.g. `DeleteObject`, `ListObjectsV2`, `DescribeInstances`. It is also
    what shows as the verb in the activity log.
  - `aws.iam_action` is the **IAM action** with its service prefix, e.g.
    `s3:DeleteObject`, `s3:ListBucket`, `ec2:DescribeInstances` — what you
    would write in an IAM policy. Best-effort (exact for the common
    operations); omitted when it can't be determined.
  - `aws.account_name` is the account's name **read live from AWS
    Organizations** (not an operator alias). It leads the human approval
    prompt so reviewers read "in account dev" instead of a bare number.
    When the name can't be resolved the field is **absent**, so a rule
    that matches on `aws.account_name` evaluates to a CEL unknown and
    **fails closed**, while rules that don't reference it are unaffected.
- **Endpoint `aws_api`** — terminates TLS, evaluates the parsed action,
  assumes the per-account role, re-signs, and brokered-dials AWS. Runs
  with **no network of its own** (`network = none`); the API call, the
  STS `AssumeRole`, and the Organizations name lookups all go through the
  gateway's audited brokered dial.
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

### Per-account base keys (optional)

By default one base key serves every account. To use **different base
keys for different accounts**, bind several `aws_account` credentials to
the endpoint and tag each with the accounts its key serves; a credential
with no `accounts` is the fallback for any account the others don't claim:

```hcl
credential "aws_account" "prod" {
  endpoint = aws_api.avocet2
  accounts = ["111111111111", "222222222222"]
}
credential "aws_account" "default" {
  endpoint = aws_api.avocet2          # no accounts = fallback for the rest
}
```

The plugin selects the credential by the request's target account. With a
single untagged credential (the default) that one key serves every
account. Organizations name resolution needs at least one bound key that
can assume the role in the management account.

## Example

```hcl
plugin "aws" {
  source  = "github.com/denoland/clawpatrol-plugin-aws"
  version = "~> 0.1"
}

credential "aws_account" "base" {    # base key entered on the dashboard
  endpoint = aws_api.avocet2
}

endpoint "aws_api" "avocet2" {
  hosts  = ["*.amazonaws.com"]
  role   = "clawpatrol-gateway"  # role assumed in each account
  region = "us-east-1"
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

`aws.action` (the API operation name) is derived from:

- `X-Amz-Target` for JSON-protocol services
  (`DynamoDB_20120810.PutItem` → `PutItem`),
- the `Action` parameter for query-protocol services
  (`DescribeInstances`),
- the request path for REST-JSON operation-as-path services
  (savingsplans: `POST /DescribeSavingsPlans` → `DescribeSavingsPlans`),
- method + path + subresource for **S3**
  (`DELETE /bucket/key` → `DeleteObject`, `GET /bucket?versions` →
  `ListObjectVersions`), and
- otherwise `METHOD path` as a last resort.

`aws.iam_action` is then derived from the service and operation
(`s3` + `ListObjectsV2` → `s3:ListBucket`).

## Account names

Account names come from **AWS Organizations**, not operator-maintained
aliases. The plugin learns the org's management account
(`DescribeOrganization`), assumes the configured `role` there, lists the
accounts (`ListAccounts`), and caches the id → name map. The assumed
`role` therefore needs `organizations:DescribeOrganization` in every
account and `organizations:ListAccounts` in the management account. When
a name can't be resolved `aws.account_name` is absent (rules on it fail
closed).

## Status

Endpoint / facet / credential, account selection, STS AssumeRole over
the brokered dial (with credential caching), SigV4 re-signing, action
parsing (including S3 operation reconstruction), and Organizations-based
account naming work and are unit-tested. Not yet covered:
chunked/streaming request bodies beyond the buffered limit, and the
regional-vs-global STS endpoint choice beyond `us-east-1`.
