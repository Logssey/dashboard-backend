# 통합 현황의 Secret 연결

통합 현황은 `detection_events`의 다른 분야 결과와 Secret 전용 모델의 현재 운영 대응 건을 **조회 시 합성**한다. Secret 원본을 이벤트 테이블에 복제하지 않으며, 기존 `domain=SECRETS` 이벤트는 중복 집계와 권한 우회를 막기 위해 이 조회에서 제외한다. 기존 레코드와 스키마는 변경하지 않는다.

## 집계와 권한

- Secret 모수는 현재 `PRODUCTION`, `IN_SCOPE`의 ResponseCase다. 동일 키의 여러 위치는 대응 건 한 건이다. 시험 데이터·정상 인벤토리·대응 건 없는 메타데이터는 더하지 않는다.
- 현재 연결 역할 및 위치별 담당자 권한을 먼저 적용한다. SECURITY/REMEDIATOR 권한이 없으면 `secretIntegration.status=NOT_AUTHORIZED`, 수는 null이다. 권한이 일부이면 `restrictedCoverage=true`이며 볼 수 있는 부분만 집계한다.
- 환경 필터는 실제 발견 위치의 환경에 적용한다. UNKNOWN은 PROD로 추정하지 않는다. 전체 조회의 한 건에 여러 환경이 있으면 `MIXED`로 표시한다. 심각도는 기존 Secret 현황과 동일하게 그 건의 권한 있는 미해결 위치에 적용 중인 최고 등급이다. `severity-v2`와 하향 보류는 유지한다.
- `totalCount`는 다른 분야 이벤트 수와 현재 Secret 대응 건 수의 합이다. 호환 필드 `unreviewedCount`는 다른 분야 미검토 이벤트와 Secret의 OPEN/IN_PROGRESS/REVALIDATION_PENDING 합이며 화면에서는 ‘확인·조치 필요’로 표시한다. 위험 수용·해결은 우선 작업 목록에서 제외한다.
- 기존 점수 산식은 유지한다. 미평가는 LOW로 환산하지 않으며 점수만으로 전체 안전성을 뜻하지 않는다. `secretIntegration`의 미평가·평가 대상 외·권한 범위를 함께 표시한다.

## API 확장

기존 `/api/v1/overview/summary`, `/risk-trend`, `/priority-findings`에 로그인 사용자의 Secret 권한을 적용한다. 기존 다른 분야 필드는 유지하고 다음을 추가한다.

- summary: `secretIntegration={status,unit:ResponseCase,origin:PRODUCTION,total,unassessedCount,notApplicableCount,restrictedCoverage}`.
- priority item: `sourceType=DETECTION_EVENT|SECRET_CASE`, `sourceId`, `detailPath`, `assessmentStatus`. Secret은 `eventId=null`, `reviewStatus=null`이고 실제 `actionStatus`를 표시한다. `detailPath=/secrets/cases/{sourceId}?origin=PRODUCTION`으로 이동한다. ID는 sourceType과 함께 식별한다.
- severity는 미평가일 때 `UNASSESSED`, 평가 대상 외이면 null이다. 환경은 Secret에 대해 UNKNOWN/MIXED도 반환한다. 담당 팀은 권한상 공개 가능한 경우만 반환한다.
- trend: 각 날짜에 `unassessed`, `notApplicable`를 추가하며 total에 포함한다. Secret은 **현재 건의 개설일과 현재 적용 등급**으로 집계하므로 과거 시점의 위험 상태를 복원한 그래프가 아니다. 다른 분야는 기존 탐지일 기준을 유지한다.
- `lastCollectedAt`는 다른 분야 최신 탐지와 현재 환경에서 읽을 수 있는 Secret 최신 관측 중 최근 값이다. 관측이 없으면 null이며 서버 시작 시각으로 채우지 않는다. 화면 문구는 ‘최근 관측’이다.

각 요청은 REPEATABLE_READ로 조회하며 공통 현황의 서로 다른 요청은 실시간 조회다. Secret 전용 분포와 매트릭스의 클릭 조회는 기존 WORKBENCH `snapshotId`로 고정한다.

검증은 `SecretOverviewProjectionIntegrationTest`에서 실제 PostgreSQL 스키마로 수행한다. 여러 위치 중복 제거, 숨은 연결·시험 데이터 제외, UNKNOWN 환경 보존, 권한 회수, 레거시 이벤트 중복 배제, 상세 링크·미평가 추이, 위험 수용의 작업 제외, 비어 있는 관측 시각을 확인한다.
