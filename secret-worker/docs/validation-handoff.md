# AWS 검증 연결 계약

`SecretFindingNormalizer.inspect(connectionId, sourceRef, content, findings)`는 한 번의 파싱에서 저장용 `Credential`과 메모리 전용 `AwsCandidate`를 함께 만든다. `AwsCandidate.material()`에는 원문 구성요소가 있으므로 수집기 콜백 안에서만 사용하고 출력, 직렬화, DB 저장을 하지 않는다. 이 객체의 `toString()`은 원문을 숨긴다.

워커는 승인된 원천 객체를 읽은 뒤 다음 순서를 따른다.

1. Gitleaks로 탐지하고 `inspect`를 호출한다. `sourceRef`는 연결 안에서 고유한 `owner/repository/path`를 사용한다.
2. `SecretJobExecutionService.persistIfLeased` 안에서 `SecretFindingRepository.recordInspection`으로 키·위치·탐지 근거를 저장한다.
3. DB 트랜잭션 밖에서 같은 `AwsCandidate.material()`을 `AwsCredentialValidator.validate`에 전달한다. 같은 실행의 같은 완전한 키는 fingerprint와 키 버전으로 모아 한 번만 검증한다. 후보는 발견 위치별로 유지한다.
4. `SecretValidationAttemptRepository.recordIfLeased`에 안전한 `Credential`과 `AwsValidationResult`를 전달한다. 저장소가 리스, 실행·작업 관계, 이번 실행에 발견된 키를 확인하고 상태·사유 코드·방법·시각만 남긴다. `false`면 리스가 만료되어 아무것도 기록하지 않은 것이다.

AWS 검증은 기본적으로 꺼져 있다. `logssey.secret.validation.aws.enabled=true`를 명시해야 STS를 호출한다. 비활성화되면 `UNCHECKED/DISABLED`, 구성요소가 부족하면 `UNCHECKED/INCOMPLETE_PAIR` 또는 `UNCHECKED/MISSING_SESSION_TOKEN`을 기록한다. `ASIA` 임시 키는 세션 토큰이 없으면 완전한 키로 병합하거나 호출하지 않는다. 합성 fixture의 키도 실제 AWS 검증에 사용하지 않는다.

키 동일성에는 `SECRET_FINGERPRINT_KEY_BASE64`와 `SECRET_FINGERPRINT_KEY_VERSION`을 Spring 설정에서 읽어 `SecretFindingNormalizer.fromBase64`로 전달한다. 키 원문과 보호키는 DB·로그에 남기지 않는다. V5 `secret_validation_attempts`는 과거 시도를 보존하며 최근 시도와 마지막 성공 판정은 각각 따로 조회한다. 부분 수집이나 실패로 이전 위치를 `MISSING`으로 바꾸지 않는다.
