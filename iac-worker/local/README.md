# IaC 보안 로컬 실행

API, iac-worker, Neo4j, PostgreSQL 을 띄우고 `demo.sh` 로 CI·CronJob 호출을 대신한다.
모두 `dashboard-backend` 디렉터리에서 실행한다 (`.env` 의 DB_*·ADMIN_* 를 쓴다).

| 순서 | 무엇 | 명령 |
|---|---|---|
| 1 | PostgreSQL | `docker compose up -d` |
| 2 | API (8080, 마이그레이션 적용) | `sh ./gradlew bootRun` |
| 3 | Neo4j (자산 그래프) | 아래 참고 |
| 4 | iac-worker | 아래 참고 |
| 5 | 데모 데이터 | `bash iac-worker/local/demo.sh` |

## Neo4j

Cartography 로 수집한 그래프가 든 로컬 Neo4j 5 가 7687 에 떠 있어야 한다.
비어 있으면 Cartography 0.143.0 을 로컬에서 한 번 돌려 채운다 (IaC 보안 ADR-03, 10/13 방식).

```bash
docker start neo4j
```

## iac-worker

```bash
sh ./gradlew :iac-worker:bootJar
IAC_GRAPH_URI=bolt://localhost:7687 \
IAC_GRAPH_PASSWORD='<Neo4j 비밀번호>' \
IAC_JOB_EXECUTOR_ENABLED=true IAC_JOB_POLL_DELAY=2s \
java -jar iac-worker/build/libs/iac-worker-0.0.1-SNAPSHOT.jar
```

- AWS 자격 증명은 기본 체인(또는 `IAC_AWS_PROFILE`)으로 읽기 전용 호출만 한다: `cloudfront:ListDistributions`(CloudFront origin), `iam:SimulateCustomPolicy`(1등급 경로 확인)
- 쿠버네티스 노드 IP 를 넣으려면 `IAC_NODE_ADDRESSES_FILE` 에 `{"노드 이름":"InternalIP"}` JSON 경로

## 데모 결과 (10/13 그래프 기준)

| PR | fixture | 판정 |
|---|---|---|
| #58 | tfstate 거부 정책 삭제 | BLOCK · CRITICAL (tfstate 1등급 경로 6) |
| #60 | IMDSv2 강제 | INFO (열린 경로 60 제거) |
| #61 | 변경 없음 | PASS |

다시 돌리면 같은 PR 의 이전 run 은 SUPERSEDED 가 되고 결과는 새 run 으로 바뀐다.
