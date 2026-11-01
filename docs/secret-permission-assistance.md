# 권한 정보 수집과 수동 확인

자동 수집은 판단에 필요한 후보 근거를 모은다. 자동 관측만으로 `PERMISSION_MAPPING`을 승인하거나 심각도를 바꾸지 않는다. 현재 `severity-v2`의 규칙·manifest·정규화 버전은 유지한다. 자동 영향 판단과 720개 정책은 포함하지 않는다.

## 수집 대상과 신원

현재 승인된 검증 경로의 AWS 장기 키·임시 키, GitHub Classic/Fine-grained PAT를 대상으로 한다. 기존 결과가 VALID여도 과거 버전에 실제 신원 관측이 없으면 새 유효성 검증부터 수행한다. 새 검증은 해당 키로 확인한 AWS principal 또는 GitHub 사용자 ID를 검증 시도·발견 위치·자격 증명 revision과 연결한다. API에는 principal 유형·공급자·시각·검증 시도 ID만 반환하고 ARN·사용자 이름·원문 응답을 노출하지 않는다.

- AWS: 승인된 동일 계정의 `IAM_ACCESS_KEY_METADATA` 범위와 해당 연결에 대한 현재 SECURITY/OPERATIONS 권한을 가진 수집 연결을 선택한다. 수집용 역할로 결합된 사용자/역할의 정책만 조회한다. 수집 역할 자체의 권한을 발견 키 권한으로 사용하지 않는다. 계정·principal ID가 다르면 후보 capability를 만들지 않는다.
- GitHub: 새로 승인된 `/user` 검증에서 받은 사용자와 폐쇄 목록으로 정규화한 Classic PAT scope를 재사용한다. 별도 App 조회나 새 토큰 권한 검사를 수행한 것으로 표시하지 않는다. 공급자 관측 시각과 6시간 만료는 원래 유효성 검증 기준을 유지한다. Fine-grained PAT에서 권한 목록을 확인하지 못하면 권한 미확인으로 남긴다. 저장소를 읽는 GitHub App 권한은 발견한 PAT 권한이 아니다.

AWS IAM 조회에는 검증한 principal의 GetUser/GetRole, 사용자·그룹·역할의 연결/인라인 정책과 관리형 정책 버전 읽기가 필요하다. 기존 소스 읽기 역할에 이런 권한이 없으면 부분 확인으로 남긴다. 이 기능이 IAM 권한을 생성하거나 확대하지 않는다. 제한된 정책 수·그룹 수와 페이지 한계를 넘으면 부분 확인을 표시한다. 새 이름이나 자원 경로를 API 요청으로 입력할 수 없다.

정책 문서의 Allow는 **가능한 capability 후보**다. 명시적 Deny, 조직 제한, 자원 정책, 조건, 권한 경계와 임시 세션 제한을 모두 평가한 실제 유효 권한이라는 의미가 아니다. 현재 관측은 PARTIAL이며 부족한 범위를 함께 반환한다. 정책 원문은 메모리에서 처리하고 후보에는 폐쇄된 capability, 수집 범위 상태, 사유, 문서 수와 digest만 저장한다. 원문 키·헤더·공급자 오류 본문은 저장하지 않는다.

## API

모든 경로의 접두사는 `/api/v1/secrets/occurrences/{occurrenceId}/permission-assistance`다.

| 요청 | 용도 |
|---|---|
| `GET` | 현재 신원·수집 가능 여부·허용 수집 연결·최근 요청·보완 작업 |
| `POST /requests` | `{expectedContextVersion,idempotencyKey,collectorConnectionId?}`로 비동기 작업 등록. 202와 requestId/jobId 반환 |
| `GET /requests/{requestId}` | 실제 작업 상태와 관측 결과 확인 |
| `GET /observations/{observationId}/preview` | 최신 contextVersion/evidenceRevision, 관측 후보, 실제 사용 가능한 부모 근거, 확인/제외 capability |
| `POST /observations/{observationId}/confirm` | 추가 근거를 검토한 사람의 명시적인 수동 권한 확인 |
| `POST /observations/{observationId}/reject` | 검토 후보 제외. 사유는 NOT_APPLICABLE/INSUFFICIENT_EVIDENCE/IDENTITY_MISMATCH |

기본 GET은 기존 capability에 더해 `requestReadiness`를 제공한다. `checks`는 기능 설정·담당 권한·지원 유형·키 구성·원천 상태·현재 키 주체·조회 연결 순서의 실제 요청 조건이며, 상태는 READY/BLOCKED/WAITING/UNSUPPORTED다. `nextAction`은 현재 먼저 해결할 작업 코드다. 이 정보는 기존 요청 검사를 설명하며 권한이나 근거를 대신하지 않는다.

현재 키 주체가 없으면 조회 연결은 WAITING이다. 같은 계정·원천을 아직 대조할 수 없기 때문에 이 단계에서는 `APPROVED_COLLECTOR_REQUIRED`를 반환하지 않는다. 유효성 확인 후 실제로 적격 연결이 없을 때 별도 연결 설정 작업을 안내한다. 조회 준비 완료는 권한 자료 수집 또는 담당자 확정 완료를 의미하지 않는다.

확인 요청은 `{expectedContextVersion,expectedEvidenceRevision,idempotencyKey,attestation:true,evidenceRef,observedAt,validUntil,facts,sourceRefs}`다. `facts`는 기존 수동 PERMISSION_MAPPING 형식(capability, targetScope 및 네 종류 coverage)이며 모두 COMPLETE를 확인해야 한다. 관측에 없는 capability는 선택할 수 없다.

체크박스는 근거를 대신하지 않는다. 실제 현재 검증 시도(BINDS_IDENTITY), 승인된 자산 분류(CLASSIFIES), 보안 담당자가 수락한 PROVIDER_REFERENCE 조사 이력(ASSERTS/LIMITS)이 모두 필요하다. 이 부모 근거는 기존 provenance 검사를 통과해야 한다. 부족하면 기존 자산 분류·조사 작업으로 연결한다. 관측을 승인된 수동 근거로 이름만 바꾸어 쓰지 않는다.

`observedAt`은 **사람이 추가 근거까지 확인한 시각**이며 공급자 관측보다 앞설 수 없다. 공급자 관측 시각은 후보 원장에 따로 보존한다. `validUntil`은 후보의 원래 만료를 넘길 수 없다. 보완 근거를 나중에 추가해도 소스·신원이 그대로면 후보를 재사용할 수 있다. 미리보기 뒤 근거가 바뀌면 새 미리보기가 필요하다. 다른 scope/자격 증명/신원/소스 버전이나 수집 승인으로 바뀌면 후보는 다시 수집해야 한다.

실제 수동 확인은 기존 `SecretRiskEvidenceService`를 호출해 `source_kind=MANUAL`, `manual-evidence-v1`로 **새 사람이 제출한 근거**를 만들고 후보 검토 원장에서 그 ID를 연결한다. 이후 기존 평가 작업과 하향 HOLD/검토 절차가 적용된다. 수집 후보 자체는 위험도 입력이 아니다.

## 실행과 실패

API와 워커에 `SECRET_PERMISSION_ASSISTANCE_ENABLED=true`를 맞춘다. 기본값은 false다. 워커는 기본 30초 간격으로 등록된 ENRICH/PERMISSION_ASSISTANCE 작업을 확인한다. 별도 원장이나 무리스 큐를 만들지 않고 공통 `secret_jobs`의 token/generation/만료/재시도를 사용한다. ENRICH에는 ScanRun이 없으며 원천 파일 검사·탐지·coverage 성공으로 계산하지 않는다. 요청 한 건의 관측을 실행하며 자동으로 권한 조치를 하지 않는다.

원래 위치와 수집 연결의 현재 권한·승인 범위·revision, 실제 신원과 비교 가능한 기준을 실행 전과 공급자 호출 전, 저장 전 다시 검사한다. 변경 또는 권한 회수는 취소로 남긴다. 만료 리스의 이전 실행자는 결과를 쓸 수 없다. 관측 결과는 추가 전용이며 재수집은 새 요청으로 남긴다.

관측 완료와 권한 완전 확인은 다르다. IAM 403·부분 페이지·알 수 없는 제한은 PARTIAL과 사유로 보존한다. 잘못된 계정/principal은 capability를 만들지 않는다. 운영 상태의 PERMISSIONS heartbeat, 작업 대기·리스·실패와 최근 성공을 함께 확인한다. 이 문서의 기능 설명은 실제 AWS/GitHub 운영 대상으로 검증을 수행했다는 뜻이 아니다.
