# Secret DB 통합 테스트 실행

기본 실행 경로는 Testcontainers의 PostgreSQL 18.6이다. API·워커의 선택 테스트는 같은 Flyway 마이그레이션과 실제 DB 제약을 검증한다.

Docker를 사용할 수 없는 개발 환경에서는 `SecretTestPostgres`를 사용하는 테스트에 한해 별도의 로컬 PostgreSQL 18 시험 클러스터를 사용할 수 있다. 애플리케이션 DB URL은 사용하지 않는다.

| 환경변수 | 조건 |
|---|---|
| `SECRET_TEST_POSTGRES_URL` | `jdbc:postgresql://127.0.0.1:<port>/secret_<시험관리DB명>` |
| `SECRET_TEST_POSTGRES_USER` | `secret_`로 시작하는 시험용 사용자 |
| `SECRET_TEST_POSTGRES_PASSWORD` | 해당 시험 클러스터의 암호. 로컬 시험 인증 방식에 따라 빈 값 가능 |

서버의 `cluster_name`은 `logssey-secret-<시험이름>-tests`여야 한다. 도구는 loopback·시험 관리 DB명·사용자·클러스터 표식과 PostgreSQL 18 버전을 확인한 뒤 fixture마다 별도 무작위 DB를 만든다. 조건이 맞지 않으면 실행을 거부한다. 생성한 DB는 조사할 수 있도록 보존하며, 시험 클러스터의 종료·정리는 운영자가 관리한다. 외부 DB 설정을 지정하지 않으면 기존 컨테이너 경로를 그대로 사용한다.

API/워커 작업을 정확히 지정해 다른 하위 프로젝트에 테스트 이름 필터가 전달되지 않게 한다.

```powershell
.\gradlew.bat :test --tests 'com.logssey.secret.response.SecretRevalidationServiceIntegrationTest' --tests 'com.logssey.secret.response.SecretLocationScopePolicyTest'
.\gradlew.bat :test --tests 'com.logssey.secret.risk.SecretSeverityAssessmentIntegrationTest' --tests 'com.logssey.secret.risk.SecretRiskEvidenceIntegrationTest' --tests 'com.logssey.secret.risk.SecretSeverityOverrideIntegrationTest' --tests 'com.logssey.secret.risk.SecretSeverityEngineTest'
.\gradlew.bat :secret-worker:test --tests 'com.logssey.secretworker.aws.AwsSecretJobProcessorTest' --tests 'com.logssey.secretworker.SecretRevalidationResultTest'
```

이 환경변수는 테스트 프로세스에만 공급한다. 서비스·개발 DB 설정이나 보호 자격 증명을 시험용으로 덮어쓰지 않는다. 공급자 호출을 모의하는 DB 회귀와 실제 계정·원천의 실증은 구분한다.
