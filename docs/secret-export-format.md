# 시크릿 결과 내보내기 형식

키·노출 위치 화면의 결과를 다른 보안 도구로 옮길 때 쓰는 파일 형식을 설명한다.

- API: `GET /api/v1/secrets/exports?format=<형식>&snapshotId=<화면 기준 ID>&(키 목록과 같은 필터)`
- 형식: `sarif`, `logssey-json`, `gitleaks`
- 파일 이름: `logssey-secrets-<형식>-<UTC 날짜>.<sarif|json>`. 사용자나 대상 정보는 넣지 않는다.
- 응답 헤더: `Cache-Control: no-store`, `Content-Disposition: attachment`

## 무엇이 들어가고 무엇이 빠지는가

| 들어가는 것 | 빠지는 것 (절대 넣지 않음) |
|---|---|
| 마스킹 라벨, 발급처, 키 유형, 탐지 규칙 이름 | 키 원문 |
| 발견 위치(GitHub 저장소·브랜치·경로·줄, 노션 페이지·블록, AWS 리전·자원) | HMAC 지문(`fingerprint`, `candidate_locator`) |
| 노출 상태(`exposure`), 공개 범위(`exposureRange`) | 노션·Slack 등 원본 본문 |
| 위험도, 인증 확인 결과, 존재 상태, 조치 상태 | 원본 경로 참조 원문, 연결 인증 정보, 키 소유자·외부 참조 |
| 처음·마지막 발견 시각, 최근 탐지 시각 | 검색어 원문(`hasSearch` 여부만 남김) |

위치 좌표는 화면의 위치 API와 같은 `SecretSourceDetails.describe()` 결과만 쓴다. 경로에 키처럼 보이는 문자열이 있으면 `[마스킹]`으로 바뀌며, 좌표를 확인할 수 없는 위치는 `UNAVAILABLE`과 안전 라벨만 남는다.

## 권한

화면과 같은 규칙을 따른다. 화면에서 볼 수 없는 위치는 파일에도 나오지 않는다.

1. `SECURITY` 또는 `REMEDIATOR` 역할이 있어야 한다. `OPERATIONS`만 있으면 403.
2. `snapshotId`는 본인이 키 목록 화면에서 받은 것이어야 하며, 필터가 같아야 한다. 다르면 404 또는 409.
3. 스냅샷 이후 권한이 바뀌었거나 볼 수 없게 된 위치가 있으면 409. 화면을 새로고침한 뒤 다시 내보낸다.
4. 스냅샷에 저장된 위치를 위치별 권한 조건과 한 번 더 교차한다. `REMEDIATOR`는 본인 또는 팀에 배정된 위치만 받는다.
5. 키 10,000개를 넘으면 413.

내보낼 때마다 `secret_audit_events`에 `SECRETS_EXPORTED`를 기록한다. 누가(`actor_user_id`), 언제(`occurred_at`), 그리고 `safe_changes`에 형식·키 수·위치 수·필터·`restrictedCoverage`를 남긴다.

## Logssey JSON (`logssey-json`)

```json
{
  "schema": "logssey.secret-export",
  "schemaVersion": "1.0",
  "generatedAt": "2026-11-19T01:02:03Z",
  "asOf": "2026-11-19T01:00:00Z",
  "restrictedCoverage": false,
  "filters": { "origin": "PRODUCTION", "source": "ALL", "hasSearch": "false", "...": "..." },
  "keyCount": 1,
  "locationCount": 2,
  "items": [ { "...": "아래 표" } ]
}
```

| 필드 | 설명 |
|---|---|
| `schema`, `schemaVersion` | 형식 이름과 버전. 필드를 빼거나 뜻을 바꾸면 버전을 올린다. |
| `generatedAt` | 파일을 만든 시각(UTC) |
| `asOf` | 화면 조회 기준 시각. 파일 내용은 이 시점의 스냅샷 기준이다. |
| `restrictedCoverage` | `true`면 열람 가능한 위치만 담긴 일부 결과다. 전체 범위의 결론으로 쓰지 않는다. |
| `filters` | 화면 필터. 검색어 원문 대신 `hasSearch`(사용 여부)만 담는다. 실행 필터가 있으면 `runId`도 담는다. |
| `keyCount` / `locationCount` | 고유 키 수 / 위치(행) 수 |
| `items[].credentialSetId` | Logssey 키 번호. 같은 키의 위치를 묶을 때 쓴다. |
| `items[].occurrenceId` | Logssey 위치 번호. 도구 간 중복 판단 기준이다. |
| `items[].maskedLabel` | 마스킹 라벨(예: `AWS ••••1234`) |
| `items[].issuer`, `credentialType` | 발급처, 키 유형 |
| `items[].ruleId` | 가장 최근 탐지 규칙. 기록이 없으면 `unavailable` |
| `items[].severity` | 키 위험도: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNASSESSED` |
| `items[].validationStatus` | 인증 확인 결과: `VALID`, `INVALID`, `UNKNOWN`, `UNCHECKED` |
| `items[].source`, `environment`, `origin` | 발견 플랫폼, 자원 환경, 조회 출처(운영·테스트 등) |
| `items[].location.kind` | `GITHUB_FILE`, `NOTION_PAGE`, `AWS_RESOURCE`, `UNAVAILABLE` |
| `items[].location.label` | 화면과 같은 위치 표시 문구 |
| `items[].location.logicalName` | 파일이 아닌 위치까지 포함한 논리 경로. 예: `notion/pages/<pageId>/blocks/<blockId>` |
| `items[].location.repository`, `branch`, `path`, `startLine`, `endLine` | GitHub 파일 좌표 |
| `items[].location.notionPageId`, `notionBlockId` | 노션 페이지·블록 ID. 제목에서 발견되면 블록은 `null` |
| `items[].location.awsRegion`, `awsResource` | AWS 좌표 |
| `items[].exposure` | 노출 상태: `ABNORMAL`(비정상 노출), `NORMAL`, `UNKNOWN` |
| `items[].exposureRange` | 공개 범위: `BROAD`(웹 공개 등 넓게 열림), `BOUNDED`, `UNKNOWN` |
| `items[].presence` | 현재 위치에 남아 있는지: `PRESENT`, `MISSING`, `UNKNOWN` |
| `items[].actionStatus` | 조치 상태: `OPEN`, `IN_PROGRESS`, `REVALIDATION_PENDING`, `RESOLVED`, `NO_CASE` |
| `items[].firstSeenAt`, `lastSeenAt`, `detectedAt` | 처음 발견, 마지막 확인, 최근 탐지 시각(UTC) |

## SARIF 2.1.0 (`sarif`)

- 결과 하나 = 위치 하나. `kind`는 항상 `fail`이다(DefectDojo는 `fail`이 아닌 결과를 건너뛴다).
- `level`: `CRITICAL`·`HIGH`는 `error`, `LOW`는 `note`, 나머지는 `warning`
- GitHub 파일: `physicalLocation.artifactLocation.uri`에 저장소 안 경로를 넣고(`uriBaseId: SRCROOT`), `region.startLine/endLine`에 줄을 넣는다. 저장소·브랜치는 `logicalLocations`(`kind: module`)에 넣는다.
- 노션·AWS 등 파일이 아닌 위치: `physicalLocation` 없이 `logicalLocations`(`kind: resource`)만 쓴다. 노션은 블록과 페이지 두 단계로 적는다. 파일 칸이 없는 도구에서도 보이도록 `message.text`에 논리 경로를 함께 적는다.
- `partialFingerprints["logsseyOccurrence/v1"]` = 위치 번호. HMAC 지문을 쓰지 않는다.
- `result.properties`에 위 Logssey JSON의 상태 값을 담는다. `run.properties.logssey`에는 메타데이터를 담는다.
- **GitHub 코드 스캐닝 주의:** 업로드는 저장소 하나 단위다. 여러 저장소나 노션 위치가 섞인 파일은 일부 결과만 보일 수 있다(`run.properties.notice`).

## Gitleaks 호환 JSON (`gitleaks`)

gitleaks v8 보고서처럼 항목의 JSON 목록으로 만든다. DefectDojo의 **Gitleaks** 스캔 유형으로 가져온다.

| 필드 | 값 |
|---|---|
| `Description` | `<발급처> <키 유형> (<규칙>)`. DefectDojo가 현재 형식으로 인식하려면 꼭 있어야 한다. |
| `File` | GitHub는 `<저장소>/<경로>`, 그 밖에는 `logicalName`(노션은 `notion/pages/…/blocks/…`) |
| `StartLine`, `EndLine` | 줄. 줄 정보가 없으면 0 |
| `Secret`, `Match` | **마스킹 라벨**. 원문을 넣지 않는다. |
| `RuleID` | 탐지 규칙 |
| `Date` | 최근 탐지 시각(없으면 마지막 확인 시각) |
| `Message` | 화면 위치 표시 문구 |
| `Tags` | `source:`, `severity:`, `exposure:`, `exposure-range:`, `presence:`, `status:`, `validation:` |
| `Fingerprint` | `<File>:<RuleID>:<StartLine>`. HMAC 지문이 아니다. |
| `Commit`, `Author`, `Email`, `SymlinkFile` | 빈 문자열(개인 정보와 커밋 정보는 넣지 않음) |

DefectDojo의 Gitleaks 파서는 위험도를 항상 High로 넣는다. Logssey 위험도는 `Tags`의 `severity:`로 확인한다.
근거: DefectDojo `dojo/tools/gitleaks/parser.py`(커밋 `78fc314f76208a70221df01e63f2ec780697ed65`), `dojo/tools/sarif/parser.py`(커밋 `ba230313cc2a0ab33a00ded2e49db661723558da`).
