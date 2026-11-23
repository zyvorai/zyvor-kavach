# Infrastructure-as-code exposure checks (Terraform plan JSON and CloudFormation)

Offline and observation-only: the analyst sends `terraform show -json plan.out > plan.json` output or a CloudFormation template to `kavachctl inspect config FILE` / `POST /v1/inspect/config`. Kavach never calls a cloud API, runs Terraform, resolves a stack or fetches a module. Checks are the existing configuration-assessment policies (`internal/edr/configpolicies/iac.json`, 17 policies, same loader and self-tests as [config-assessment.md](config-assessment.md)); findings have weight 0 and the report is `not_scored`.

## Formats

* `tfplan`: Terraform plan JSON. `resource_changes[].change.after` is read for every resource that is not being deleted (a resource the plan removes is not reported); if `resource_changes` is empty, `planned_values` is walked instead. Sniffed from `"resource_changes"` or `"planned_values"` plus `format_version`.
* `cfn`: CloudFormation JSON, or YAML. YAML short-form intrinsics (`!Ref`, `!Sub`, `!GetAtt`, `!If` and the like) have the tag stripped so the safe YAML-subset parser can read the rest; flow maps and anchors are still rejected and reported as a parse note (a partially parsed template is evaluated for what was parsed). Sniffed from `AWSTemplateFormatVersion` or `Type: AWS::Service::Resource`.

Provider coverage today: AWS (security groups and rules, S3 ACLs, public access blocks and policies, IAM identity and trust policies, queue/topic/key/repository/secret policies, RDS, EBS, instance metadata), plus Azure (storage account, network security rule) and Google (firewall, bucket IAM) for Terraform plans.

## How it works

`inspect_config_iac.go` normalises each resource and emits a `risk.<name>` setting whose value is the resource address when a known-bad literal is present. A policy then says "no `risk.<name>`". Values that are unknown at plan time, variables, intrinsic functions and computed attributes never produce a marker, so a missing finding is not a pass for that resource. A plan or template with no resources reports `not_applicable`.

| Policy | Severity | Pattern |
|---|---|---|
| `iac-sg-open-all` | critical | 0.0.0.0/0 or ::/0 ingress on all ports or all protocols |
| `iac-sg-open-admin` | high | world ingress to 22, 23, 3389, 5900, 5985, 5986 |
| `iac-sg-open-data` | high | world ingress to common datastore ports |
| `iac-s3-public-acl` | high | public-read, public-read-write, authenticated-read |
| `iac-s3-pab-disabled` | medium | any public-access-block protection false |
| `iac-s3-policy-public` | high | bucket policy Allow with Principal `*` and no Condition |
| `iac-resource-policy-public` | high | the same for SQS, SNS, KMS, ECR, Secrets Manager, Lambda permission |
| `iac-iam-admin-wildcard` | high | Allow Action `*` on Resource `*` |
| `iac-iam-service-wildcard` | medium | Allow `svc:*` on Resource `*` |
| `iac-iam-passrole-any` | medium | Allow `iam:PassRole` on `*` |
| `iac-iam-trust-any` | high | role trust policy with Principal `*` and no Condition |
| `iac-rds-public` | high | PubliclyAccessible true |
| `iac-storage-unencrypted` | medium | encryption explicitly false (RDS, EBS) |
| `iac-ec2-imdsv1` | medium | metadata `http_tokens` optional |
| `iac-azure-storage-public` | high | `allow_nested_items_to_be_public` true (plan only) |
| `iac-storage-no-tls` | medium | `https_traffic_only_enabled` false (plan only) |
| `iac-bucket-public-principal` | high | GCS IAM `allUsers` / `allAuthenticatedUsers` (plan only) |

## Limits

Per-resource literals only: modules, `count`/`for_each` expansion, data sources, SCPs, permission boundaries and runtime state are not evaluated, so an over-broad rule that a boundary neutralises is still reported and a risk built from variables is missed. Up to 5,000 resources are read (a note says when truncated); policy documents over 64 KiB are skipped; JSON is decoded with the standard library decoder and hostile shapes (wrong types, deep nesting, malformed policy strings) are ignored rather than trusted. The thresholds are this project's wording and not a benchmark; passing is not a compliance statement.

Findings from this analyzer can be fed to [attack-paths.md](attack-paths.md): `POST /v1/exposure/attack-paths/evaluate` classifies `cfg-iac-*` findings into exposure, privilege and data signals.
