# Secret 검사 생략 진단과 활성화

수집 플랫폼의 접근 권한, 내용을 읽는 범위, 발견한 키로 인증을 요청하는 허용은 서로 다르다.
`검사 완료`는 작업 종료이며 모든 키의 인증 완료를 의미하지 않는다.

## 확인 순서

1. 실행의 `secret_run_scopes.snapshot_content_type`을 확인한다. `*_METADATA`만 있으면 목록/상태 조회다. 내용 탐지와 인증 확인을 하지 않는 것이 정상이다.
2. 내용 검사에서는 대상별 `object_count`, `detection_stage_status`, `detection_reason_code`를 확인한다. 파일 수/크기 제한, 바이너리 제외, 수집 실패를 키 후보 0건과 구분한다.
3. 인증 확인은 해당 실행과 **현재 attempt_no**의 `secret_validation_attempts`를 조회한다. `UNCHECKED`의 `reason_code`별 건수가 실제 미실행 이유다. 재사용된 확정 결과는 `secret_validation_reuses`에서 별도로 확인한다.
4. 과거 `STAGE_SUMMARY`의 `NO_CANDIDATES`만으로 실행 전체에 후보가 없었다고 판단하지 않는다. 대상별 이유의 최솟값을 대표 사유로 저장한 실행이 있다. 진행 API는 실제 검증 기록으로 이를 보정하며 원본 이벤트는 보존한다.

## GitHub와 Notion의 발견 키 인증 확인

API와 secret-worker의 설정을 **함께** 맞춘다. API는 화면과 요청 가능 조건을, 워커는 실제 실행을 판단한다.

```properties
logssey.secret.validation.aws.enabled=true
logssey.secret.validation.github.enabled=true
logssey.secret.validation.notion.enabled=true
```

이는 서버가 해당 검증 방식을 지원하도록 켜는 설정이다. 그 자체로 모든 연결에서 인증 요청을 보내지는 않는다.

- 연결 관리 → 해당 연결 → **키 검증 설정**: 연결 검증을 허용하고 검증할 키 발급 서비스를 선택한다. GitHub 저장소에서 AWS 키가 발견될 수 있으므로 수집 플랫폼과 발급 서비스를 동일시하지 않는다.
- **검사 대상별 허용 설정**: 실제 인증을 확인할 대상만 승인한다. 승인자와 변경 이력은 기존 설정 API에서 기록한다. DB 일괄 UPDATE로 승인을 만들어내지 않는다.
- 다시 검사한 후 `newRequestCount`, `completedRequestCount`, `uncheckedReasons`, `reusedResultCount`를 구분해 확인한다. 과거 실행 결과는 설정 변경만으로 갱신되지 않는다.

`SOURCE_GUARD_BLOCKED`, `SYNTHETIC_FIXTURE`는 합성 표본/보호 설정이며 자동으로 해제하지 않는다. `INCOMPLETE_PAIR`, `MISSING_SESSION_TOKEN`은 인증 재료가 부족한 상태이므로 다른 파일의 값을 임의로 결합하거나 유효로 표시하지 않는다.

## AWS 내용 검사

`s3:ListAllMyBuckets`만으로는 S3 파일 내용을 읽을 수 없다. 사용자 AWS 계정 대신 **실제 워커 역할**의 정책을 확인한다.

- API와 워커의 `logssey.secret.aws.content.enabled=true`가 필요하다.
- 승인된 S3 객체에는 `s3:GetObject`가 필요하다. 버전 읽기는 사용 방식에 따라 `s3:GetObjectVersion`, SSE-KMS는 해당 키에 대한 `kms:Decrypt`도 필요하다.
- Secrets Manager 값과 SSM 값은 각각 승인된 리소스의 `secretsmanager:GetSecretValue`, `ssm:GetParameter` 및 필요한 복호화 권한이 있어야 한다.
- 현재 구현은 `AWS_S3_OBJECT_CONTENT`의 **정확한 객체 키**를 읽는다. 폴더 URI나 `*`는 하위 객체 수집을 의미하지 않는다. 폴더 수집은 prefix 승인, 페이지네이션, 개수/총 크기 제한, 객체별 실패 및 수집 범위 기록을 갖춘 별도 기능으로 구현해야 한다.
- 내용 읽기가 가능한 뒤에도 발견한 키의 인증 확인에는 위의 연결 설정과 대상별 승인이 필요하다.

## 검증

메타데이터 조회는 “목록 조회 완료”로 구분하며 인증 결과 0건을 표시하지 않는다. 내용 검사에서 후보가 있지만 인증이 제한되면 “인증 미확인”과 사유별 건수를 표시한다. 후보 없음, 설정 제한, 검증 실패, 이전 결과 재사용을 서로 바꾸어 표시하지 않는다.
