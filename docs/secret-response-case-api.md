# Secret 대응 건 및 담당자 API (10/15 범위)

V7은 기존 Secret 인벤토리와 분리된 대응 건, 위치 연결, 담당자 변경 이력, 감사 이벤트, Secret 전용 역할을 만든다. 기존 발견을 대응 건으로 자동 승격하거나 과거 데이터를 소급 생성하지 않는다. 현재 수집기는 발견 위치의 `exposure_status`를 `UNKNOWN`으로 저장하고, 기존 승인 범위의 `response_origin`은 `UNCLASSIFIED`다. 따라서 별도의 근거 판정과 범위 분류가 이루어지기 전에는 실제 데이터에서 대응 건을 열 수 없다.

## 경로

| Method | 경로 | 계약 |
|---|---|---|
| GET | `/api/v1/secrets/cases?page=0&size=20&origin=PRODUCTION` | 현재 대응 건 목록 `{items,total,page,size}`. `origin`은 `PRODUCTION` 또는 `TEST`이며 기본값은 `PRODUCTION`이다. 두 범위는 섞이지 않는다. |
| GET | `/api/v1/secrets/cases/{caseId}` | 마스킹된 키 식별자, 단계, 담당자, 버전, `caseOrigin`, 개설 위치 ID·사유, 담당자 변경 이력을 조회한다. 원문 키와 원천 콘텐츠는 반환하지 않는다. |
| POST | `/api/v1/secrets/{secretId}/cases` | `{occurrenceId,reason:"ASSESSED_EXPOSURE"}`. 성공 시 201과 대응 건 상세를 반환한다. 클라이언트가 운영·시험 구분을 정하지 않는다. |
| GET | `/api/v1/secrets/assignees?caseId={caseId}` | 해당 건의 모든 연결 범위를 담당할 수 있는 조치 담당자와 검증된 팀 목록을 반환한다. |
| PATCH | `/api/v1/secrets/cases/{caseId}/assignment` | `{team,assigneeUserId,reason,expectedVersion}`. 변경 후 상세를 반환한다. |

개설은 서버가 저장된 `CONFIRMED` 키와 `ABNORMAL`·`PRESENT` 발견 위치, 활성 GitHub 연결, 활성 승인 범위, 분류 완료된 `response_origin`을 함께 검사한다. 범위 분류는 `UNCLASSIFIED`, `PRODUCTION`, `TEST`이며 기본값은 `UNCLASSIFIED`다. 운영 목록은 시험 건을 포함하지 않고, 시험 건에는 `caseOrigin=TEST`가 명시된다. 같은 키에 시험·운영 노출이 각각 확인되면 현재 대응 건은 각 범위에 한 건씩 독립적으로 존재할 수 있다. IAM `METADATA_ONLY`, 불완전 후보, AWS 비밀 저장소의 정상 값 존재, 유효성 `UNKNOWN`·`UNCHECKED`만으로는 개설할 수 없다. 현재 범위를 분류하거나 노출을 판정하는 API는 아직 없으므로, 운영 승인 절차 없이 범위를 임의로 운영으로 분류하지 않는다.

담당자 변경 사유는 `INITIAL_ASSIGNMENT`, `OWNERSHIP_CHANGE`, `TEAM_TRANSFER`, `UNASSIGNED`, `OTHER` 중 하나다. 자유 입력 사유로 키 원문을 감사 테이블에 저장하지 않는다. 개인은 해당 건의 모든 연결 범위에 활성 `REMEDIATOR` 권한이 있어야 한다. 팀을 지정하면 활성 팀 소속도 확인한다. 팀만 지정할 때는 그 팀에 자격 있는 조치 담당자가 있어야 하고, 개인·팀을 모두 비우면 미지정으로 되돌린다. `expectedVersion`이 다르면 409이며 버전 증가, 담당자 변경 이력, 감사 이벤트는 하나의 트랜잭션에서 저장한다. 개설과 담당자 지정은 기존 세션·CSRF 검사를 거친다.

`dashboard_users.role=ADMIN`은 Secret 권한이 아니다. 기존 계정에 명시적으로 권한을 부여할 때 개발 환경에서는 `SECRET_BOOTSTRAP_SECURITY_LOGIN_ID`, `SECRET_BOOTSTRAP_REMEDIATOR_LOGIN_ID`, 선택적인 `SECRET_BOOTSTRAP_REMEDIATOR_TEAM`을 설정할 수 있다. 최초 실행에서 별도 `secret_role_grants` 행이 기록되고, 이후 역할을 취소하면 재시작해도 자동 복구하지 않는다. 이 부트스트랩은 **개발 환경에서 승인된 기존 계정에만** 사용한다. 운영 환경의 역할 부여·연결별 범위와 범위 분류는 별도 승인·감사 절차로 관리해야 한다. 아무 설정이 없으면 대응 건 변경은 403으로 닫힌다.
