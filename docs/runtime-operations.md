# Runtime 운영과 데이터 보존

Runtime 수집 데이터는 조사 가능성과 민감정보 최소 보관을 함께 만족해야 한다. Finding과
정규화 이벤트의 연결은 유지하되, 기본 30일이 지난 raw JSON payload만 비식별화한다.

## Raw payload 수명주기

1. 수집 시 마스킹을 먼저 적용한다.
2. 저장되는 마스킹 payload의 SHA-256과 `payloadRetentionUntil`을 기록한다.
3. 만료 후 payload를 `purged`, `sha256`, `purgedAt`만 가진 JSON으로 교체한다.
4. Raw Event ID, 처리 상태, 수신 시각, 정규화 Event 및 Finding 연결은 보존한다.

기존 데이터는 배포 시 수신 시각으로부터 30일의 보존 기한을 부여한다. 기존 payload는
애플리케이션을 거쳐 저장되지 않았으므로 SHA-256을 소급 생성하지 않는다.

## 정리 작업

- 기본 실행 시각: 매일 UTC 03:15(한국 시간 12:15)
- 기본 payload 처리량: 실행당 1,000건
- 기본 수집 rate-window 보존 기간: 7일
- PostgreSQL transaction advisory lock을 사용하므로 여러 Backend replica 중 하나만 실행한다.
- 만료 payload는 `FOR UPDATE SKIP LOCKED`로 선택해 운영 중 수집을 장시간 막지 않는다.

관리자는 필요할 때 정리 작업을 직접 실행할 수 있다.

```text
POST /api/v1/runtime/operations/maintenance
```

운영 상태 조회:

```text
GET /api/v1/runtime/operations/health
```

최근 15분의 `GROUPED`, `SUPPRESSED`, `RATE_LIMITED`, `IGNORED`, `FAILED` 수와 payload
파기 적체, 마지막 정리 결과를 반환한다. 최근 실패가 있으면 `DEGRADED`, 폭주 제한이나
파기 적체가 있으면 `ATTENTION`, 그 외에는 `HEALTHY`다.

## 환경 변수

```text
RUNTIME_RAW_PAYLOAD_RETENTION=P30D
RUNTIME_RATE_WINDOW_RETENTION=P7D
RUNTIME_MAINTENANCE_BATCH_SIZE=1000
RUNTIME_MAINTENANCE_CRON=0 15 3 * * *
```

보존 기간을 줄일 때는 조사·감사 요구사항을 먼저 확인해야 한다. 운영에서 기간을 늘리는
경우에도 저장 비용과 payload 내 잔여 민감정보 위험을 함께 검토한다.
