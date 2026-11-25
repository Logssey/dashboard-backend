# 사용자 키 형식 등록 (커스텀 키 패턴, 데모 MVP)

사내에서 쓰는 키 모양을 화면 폼으로 등록하면 서버가 탐지 규칙(정규식)을 자동으로 만든다. 사용자는 정규식을 쓰지 않는다. 다음 스캔부터 내장 규칙(AWS·Notion)과 함께 검사한다.

```
접두사 rik_  +  문자 종류 16진수 소문자  +  길이 32   →   rik_[0-9a-f]{32}
```

화면: 시크릿 › **키 형식 등록** (`/secrets/key-patterns`)

## 1. 이번 데모 범위 (구현 완료)

| 구성 | 내용 |
|---|---|
| DB | `V56__create_custom_key_patterns.sql`: `custom_key_patterns` 테이블, `credentials.issuer`에 `CUSTOM` 추가 |
| 규칙 생성 | `KeyRuleCompiler`: 입력 검사 + 정규식 생성. `KeyCharset`: 문자 종류 7가지 |
| 스캐너 | `KeyRule` 인터페이스. 내장 `SecretPattern`(enum)과 DB의 `CustomKeyRule`을 `SecretScanner`가 함께 검사 |
| 저장 | 원문 미저장. 비밀값이면 HMAC 지문 + 마스킹(`rik_****5e6f`), 식별자면 `external_id` |
| API | 아래 2절 |
| 화면 | 등록 폼(실시간 규칙 미리보기·샘플 시험), 등록 목록, **지금 스캔** + 찾은 키 목록 |
| 권한 | 등록·삭제는 `dashboard_users.role = ADMIN`만 (아니면 403). 목록·미리보기·스캔은 로그인 사용자 |

### 정규식 모양과 안전장치

```
(?<![A-Za-z0-9_-])(\Qrik_\E[0-9a-f]{32})(?![0-9a-f])
```

- 앞 조건: 다른 단어 중간(`xrik_…`)에서 시작한 값은 잡지 않는다
- 뒤 조건: 더 긴 문자열(33자 이상)의 앞부분만 잘라 잡지 않는다
- 접두사는 `\Q…\E`로 감싸 글자 그대로 취급한다
- 정규식은 DB에 저장하지 않는다. 스캔할 때마다 접두사·문자 종류·길이로 다시 만들어, "고정 문자열 + 문자 클래스{n}" 모양 밖의 정규식(ReDoS 포함)이 생길 수 없다. 검사를 통과하지 못한 DB 행은 건너뛰고 스캔은 계속한다

### 입력 제한

| 항목 | 제한 |
|---|---|
| 이름 | 1~50자 |
| 접두사 | 2~20자, 영문·숫자·`_ - .` |
| 예약 접두사 | `AKIA` `ASIA` `ntn_` `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_` `secret_`로 시작 불가 (기본 규칙과 겹침) |
| 길이 | 접두사 뒤 16~128자 (마스킹이 끝 4자를 보여 주므로 최소 16) |
| 중복 | 같은 접두사·문자 종류·길이는 한 번만 (DB 유니크 제약, 409) |
| 개수 | 최대 50개 |

## 2. API

모두 세션 로그인 필요. GET이 아닌 요청은 CSRF 헤더(`X-XSRF-TOKEN`) 필요.

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/v1/credentials/custom-patterns` | 로그인 | 등록 목록, 문자 종류 목록, 한도, `canManage`(지금 사용자가 등록·삭제 가능한지) |
| POST | `/api/v1/credentials/custom-patterns/preview` | 로그인 | 저장 없이 규칙·예시 생성. `sample`을 주면 마스킹된 일치값 반환. 샘플은 저장·로그하지 않음 (최대 10,000자) |
| POST | `/api/v1/credentials/custom-patterns` | ADMIN | 등록. 201 / 400 입력 오류 / 403 / 409 중복 / 422 한도 초과 |
| DELETE | `/api/v1/credentials/custom-patterns/{id}` | ADMIN | 삭제. 204 / 403 / 404. 이미 찾은 키(`credentials`)는 지우지 않음 |
| POST | `/api/v1/credentials/scan` | 로그인 | 기존 Notion 스캔. 이제 등록한 형식도 함께 검사 |
| GET | `/api/v1/credentials?issuer=CUSTOM` | 로그인 | 등록한 형식으로 찾은 키 |

요청 예:

```json
POST /api/v1/credentials/custom-patterns
{"name": "사내 RIK 키", "prefix": "rik_", "charset": "HEX_LOWER", "length": 32, "secret": true}
```

`charset`: `HEX_LOWER` `HEX` `ALNUM` `ALNUM_UPPER` `ALNUM_LOWER` `DIGITS` `BASE64URL`

## 3. 알려진 제약 (데모에서 설명할 것)

1. **메인 탐지 흐름(secret-worker · Gitleaks)에는 아직 반영되지 않는다.** 등록한 형식은 백엔드 `SecretScanner` 경로(`/api/v1/credentials/scan`, Notion)에서만 동작한다. 이 경로는 화면 전환 기간의 호환 경로(`secret-run-api.md`)라 결과가 "키·노출 위치"·대응 관리 화면에는 나오지 않고, 키 형식 등록 화면의 "찾은 키" 목록에만 나온다.
2. **ADMIN 제한은 현재 실질적으로 모든 계정에 열려 있다.** `dashboard_users.role`이 `ADMIN` 하나만 허용되고 GitHub 로그인 신규 계정도 `ADMIN`으로 만들어지기 때문이다. 다른 역할이 생기면 코드 변경 없이 바로 제한된다.
3. 스캔 실행은 로그인 사용자 누구나 할 수 있다 (기존 동작 유지).
4. 규칙은 모든 연결·페이지에 똑같이 적용된다 (소유자·범위 없음).
5. 예약 접두사는 로그세이가 다루는 AWS·GitHub·Notion만 넣었다. Gitleaks 기본 규칙(Slack `xoxb-`, GitLab `glpat-`, Stripe `sk_live_` 등)과의 겹침은 막지 않는다.

## 4. 추가할 기능 (로드맵)

### 4.1 Gitleaks 연동: 메인 탐지 흐름에 반영 (다음 스프린트, 백엔드 1명 기준 약 2~3주 추정)

조사 결과 DB 접근(같은 DB·같은 마이그레이션)과 원문 미저장(`--redact=100` + 지문)은 그대로 이어진다. 손볼 곳:

| 작업 | 크기 | 비고 |
|---|---|---|
| Gitleaks(Go RE2)용 정규식 생성 | S | RE2는 lookaround 미지원. `(?:^\|[^A-Za-z0-9_-])(\Qprefix\E[cls]{n})(?:[^cls]\|$)` + `secretGroup=1` + `keywords=[prefix]` 형태. 컴파일러를 worker와 공유하거나 복사 |
| 스캔마다 TOML 생성, detector가 DB 규칙 읽기 | M | 지금은 `GitleaksDetector.CONFIG_TOML` 고정 문자열이고 해시를 서버 시작 시 한 번 계산 |
| normalizer에 CUSTOM 분기 | M | 모르는 rule ID는 지금 조용히 버려짐(`SecretFindingNormalizer` `matches.size()!=1`). rule ID `custom-<id>`, issuer `CUSTOM`, 타입·마스킹·`is_secret` 처리 |
| **설정 해시 정책** | **L (가장 위험)** | `configHash`가 재검사 기준선·대응 종료·전체 스캔 MISSING 판정·오탐 판정 재사용에 쓰인다. 형식을 바꿀 때마다 해시가 바뀌면 이 기능들이 초기화된다. **결정 필요**: (가) 기본 규칙 해시 + 커스텀 규칙 해시 분리 (추천) / (나) 초기화 허용 |
| 백엔드 허용 목록·프론트 라벨에 CUSTOM | S | `SecretInventoryService` 필터, `labels.ts`의 `issuerLabel`, `secrets.ts`의 `SecretIssuer` 등 |
| 실제 Gitleaks 바이너리로 통합 테스트 | M | |

부수 결정: 형식에 버전·사용 여부(enabled) 컬럼 추가 여부, 키 유효성 검증은 CUSTOM을 "검증 불가(UNCHECKED)"로 둘 것(기존 경로가 이미 이렇게 처리해 오류는 없음).

### 4.2 권한

- 실제 역할 구분: `secret_role_grants`(예: `SECURITY`)를 받은 사람만 등록·삭제하도록 변경
- 등록·삭제 감사 기록 (누가·언제·무엇을)

### 4.3 규칙 표현력

- 길이 범위(최소~최대) 지원
- 정규식 직접 입력 고급 모드 (관리자 전용, 서버에서 RE2·Java 양쪽 검증 + 시간 제한)
- 문자 종류 추가 (예: base64 `+/=`)

### 4.4 관리 기능

- 형식 사용 중지/재개 (삭제 대신)
- 연결·페이지 범위별 적용 (지금은 전체 적용)
- 형식별 탐지 건수 표시
- 예약 접두사를 Gitleaks 기본 규칙 전체와 비교

### 4.5 AI 추천

- 샘플 글에서 키 모양을 추론해 접두사·문자 종류·길이를 제안 (계획서상 로드맵 항목)

## 5. 확인한 것

- 백엔드: credential 테스트 48개 통과 (신규: `CustomKeyRuleTest`, `CustomKeyPatternServiceTest`)
- 마이그레이션: V1~V56을 Postgres 18.6에 적용, CHECK·UNIQUE 제약 동작 확인
- 프론트: `tsc -b`, `vite build`, 테스트 347개 통과
- 끝에서 끝까지 확인: 로컬 가짜 Notion 페이지로 등록 → 지금 스캔 → `rik_****5e6f`(CUSTOM)를 찾음. 33자 값·대문자 값은 잡히지 않음. DB에 키 원문이 들어간 행 0개
