# plan fixtures

`terraform show -json` 결과를 CI(iac-gate)가 민감값을 지워 올린 `plan-prod` 아티팩트 (gzip). 2026-10-19 infrastructure 테스트 PR 에서 받음.

| 파일 | 변경 | 비고 |
|---|---|---|
| `58.json.gz` | `module.iam.aws_iam_role_policy.deny_tfstate` 삭제 | #58 시나리오 |
| `imdsv2.json.gz` | prod `imds_tokens = "required"` (인스턴스 10대) | 경로 감소 |
| `nochange.json.gz` | 주석만 | 리소스 변경 0. resource_drift 3건은 모두 노이즈 |
| `drift-dns.json.gz` | `nochange` + grafana A 레코드 별칭이 콘솔에서 NLB 로 바뀐 drift 1건 | U4 확인용 파생본. 나머지는 실제 plan 그대로 |
