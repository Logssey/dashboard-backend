# Runtime security local check

`falco-run-001.json`, `falco-run-003.json`, `falco-run-004.json`, `falco-run-007.json`은
실제 Falco JSON 출력 형식에 맞춘 로컬 개발용 이벤트다. 각각 컨테이너 셸 실행,
ServiceAccount 토큰 접근, 패키지 관리자 실행, 민감 경로 쓰기를 재현한다.
백엔드의 `RUNTIME_COLLECTOR_TOKEN`과 같은 값을 헤더에 넣어 전송한다.

```bash
curl -X POST http://localhost:8080/internal/v1/runtime/events/falco \
  -H 'Content-Type: application/json' \
  -H 'X-Runtime-Collector-Token: <local collector token>' \
  -H 'Idempotency-Key: local-falco-run-001' \
  --data-binary @examples/falco-run-001.json
```

같은 `Idempotency-Key`로 다시 보내면 새 이벤트를 만들지 않고 `duplicate: true`를 반환한다.
다른 규칙은 파일명과 `Idempotency-Key`의 규칙 번호를 함께 바꿔 같은 방식으로 전송한다.

센서는 이벤트 발생 여부와 관계없이 heartbeat를 전송한다. 서버 수신 시각을 기준으로
2분이 지나면 `DEGRADED`, 5분이 지나면 `OFFLINE`으로 조회된다.

```bash
curl -X POST http://localhost:8080/internal/v1/runtime/sensors/heartbeat \
  -H 'Content-Type: application/json' \
  -H 'X-Runtime-Collector-Token: <local collector token>' \
  --data-binary @examples/falco-heartbeat.json
```

Falcosidekick raw endpoint에는 DB의 `sensorId`가 없으므로 이벤트의
`output_fields.k8s.node.name`으로 Falco 센서를 자동 등록하고 원본 이벤트에 연결한다.
