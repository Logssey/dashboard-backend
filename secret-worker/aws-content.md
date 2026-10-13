# AWS 본문 수집 경계

AWS 값 읽기는 메타데이터 수집과 별도 경로다. 이 어댑터는 단일 승인 자원만 읽는다. `AwsContentCollector.collect(scope, valueReadEnabled, maxBytes, sink)`에서 `valueReadEnabled=false`면 SDK 호출이 0회이고, 운영 설정도 기본 비활성으로 연결해야 한다. 배치 실행 시 다른 scope가 실패해도 각 scope의 안전한 실패 코드와 건수를 별도로 기록하고 다음 scope를 처리한다.

워커의 별도 설정은 `SECRET_AWS_CONTENT_READ_ENABLED=false`가 기본값이다. 이 값을 켜더라도 `SECRET_AWS_COLLECTION_ENABLED=true`, 정확한 승인 scope, 실행 프로필과 STS 계정 일치가 모두 확인되어야 본문 API를 호출하도록 작업 실행기에 연결한다. GitHub와 AWS 본문 수집은 같은 `SECRET_GITLEAKS_PATH`, `SECRET_FINGERPRINT_KEY_BASE64`, `SECRET_FINGERPRINT_KEY_VERSION`으로 탐지·정규화한다.

| content_type | approved_ref 형식 | 실제 읽기 API |
| --- | --- | --- |
| `AWS_SECRETS_MANAGER_VALUE` | `aws://<account>/<region>/secrets-manager/secret/<URL-encoded exact secret ARN>` | `GetSecretValue`의 `AWSCURRENT` |
| `AWS_SSM_PARAMETER_VALUE` | `aws://<account>/<region>/ssm/parameter/<URL-encoded exact parameter ARN>` | `GetParameter` with decryption |
| `AWS_S3_OBJECT_CONTENT` | `aws://<account>/<region>/s3/object/<bucket>/<URL-encoded exact key>` | `HeadObject`, 조건부 `GetObject` |

세 종류 모두 `history_limit=CURRENT_VALUE_ONLY`만 허용한다. `all`, 경로 prefix, 와일드카드, 메타데이터 scope는 값 수집 승인으로 해석하지 않는다. 계정은 실행 자격 증명의 STS 신원과 일치하는지 상위 작업 실행기에서 확인해야 한다. S3 호출은 `expectedBucketOwner`를 지정하고 ETag 또는 버전으로 HEAD와 GET 사이 변경을 방지한다. 공통 작업 실행기는 값 접근을 위한 별도 opt-in을 확인한 뒤 이 어댑터를 호출해야 한다.

본문은 최대 256 KiB 기본값, 1 MiB 절대 상한이고, UTF-8 텍스트만 받아들인다. NUL 및 제어 바이트, 바이너리 SecretString, 초과 크기는 탐지기에 넘기지 않는다. 승인된 한 건은 동기 callback에서 Gitleaks stdin으로만 전달하고 callback 종료 직후 소유 `byte[]`를 0으로 덮는다. SDK의 `SecretString`과 SSM `value`는 Java 불변 `String`으로 이미 생성되므로 완전한 메모리 소거는 보장하지 못한다. 이를 파일, DB, 애플리케이션 로그, GitHub에 기록하거나 전송해서는 안 된다. SDK HTTP wire logging도 켜지 않아야 한다.

Secret ARN, SSM 이름, S3 object key도 민감한 메타데이터다. `approved_ref`가 들어가는 로컬 DB와 백업의 접근 권한을 제한한다. 탐지 결과의 `sourceRef`는 원문 자원명이나 무키 SHA-256 해시가 아닌 `aws-content-scope:<scope_id>` 같은 내부 ID 기반 별칭을 사용한다. `scope_id`는 반복 실행 중에도 안정적이라 동일 위치가 중복 생성되지 않고, 승인 범위 교체 시 새 위치로 취급된다. Collector의 `Source`와 `Result`에는 자원명이나 값이 없고, 제공자 예외 메시지와 cause를 폐기하고 안전한 코드만 반환한다. UI가 위치를 조회해야 한다면 인가된 별도 경로에서 원본 승인 scope를 해석한다.

이 커밋은 수집기와 SDK fake 테스트만 추가한다. 작업 실행기, 설정, DB/API 연결과 실제 값 접근은 별도로 통합한다. 테스트는 가짜 응답만 사용하며 AWS 값 API를 호출하지 않는다.
