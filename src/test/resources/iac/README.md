# IaC plan fixtures

- `plan-raw.json`: infrastructure `policy/testdata/scrub-plan/plan.json` (terraform_data 로 만든 실제 plan, 민감값은 모두 `FIXTURE-SECRET-*`)
- `plan-scrubbed.json`: 위 파일을 infrastructure `policy/scrub-plan.sh` 로 지운 결과

다시 만들 때는 infrastructure 의 fixture 를 먼저 갱신한 뒤 같은 순서로 복사·변환한다.
