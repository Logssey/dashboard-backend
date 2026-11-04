# Reach L1 수집기

Re:Used 클러스터 안에서 CronJob으로 돌며, 지정한 네임스페이스의 실행 중인 파드 목록을 읽어 워크로드별 이미지 digest를 대시보드로 보낸다. 대시보드는 이 값으로 Finding의 배포 여부(`deployment` = `RUNNING` / `NOT_RUNNING` / `UNKNOWN`)를 채운다.

이 폴더는 **수집기 이미지의 원본**이다. 대시보드(API 서버) 이미지와 무관하며, 클러스터에 올리는 매니페스트(서비스 계정, RBAC, CronJob)는 `gitops` 저장소에 둔다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `collect.sh` | 네임스페이스마다 파드 목록 조회 → `inventory.jq`로 변환 → 대시보드에 `PUT` |
| `inventory.jq` | 파드 목록을 워크로드·컨테이너·digest만 남긴 본문으로 바꾼다. 환경 변수·실행 인자는 밖으로 나가지 않는다 |
| `Dockerfile` | Alpine(digest 고정) + `curl`·`jq`, 사용자 10001 |

## 동작

1. 파드에 자동으로 붙는 서비스 계정 토큰으로 `GET /api/v1/namespaces/<ns>/pods`를 부른다. 필요한 권한은 그 네임스페이스의 pods `list` 하나다.
2. `Running` 파드만 골라 소유자 ReplicaSet 이름에서 `pod-template-hash`를 떼어 Deployment 이름을 얻고, 같은 워크로드끼리 묶는다. 이미지를 아직 받지 않아 `imageID`가 없는 컨테이너는 뺀다.
3. Reach 전용 토큰(`/var/run/secrets/reach/token`, audience `logssey-reach-l1`)으로 `PUT $REACH_URL/internal/v1/reach/l1/workloads`에 보낸다. 대시보드는 네임스페이스 단위로 기록을 통째로 바꾼다.

한 네임스페이스가 실패해도 나머지는 보내고, 실패가 있었으면 종료 코드 1로 끝난다(Job 실패로 기록되고 `backoffLimit`만큼 다시 시도한다).

## 환경 변수

| 이름 | 예 | 설명 |
| --- | --- | --- |
| `NAMESPACES` | `reused` | 읽을 네임스페이스, 쉼표로 구분 |
| `CLUSTER` | `reused-prod` | 대시보드에 보낼 클러스터 이름 |
| `REACH_URL` | `https://<대시보드 주소>` | 끝에 `/` 없이 |

하나라도 없으면 바로 종료 코드 2로 끝난다.

## 빌드

저장소 루트의 `.dockerignore`가 허용 목록 방식이라, 이 폴더를 빌드 문맥으로 쓴다.

```sh
docker build -t reach-l1-collector:local deploy/reach/l1-collector
```

베이스 이미지 digest를 올릴 때는 아래로 새 값을 조회해 `FROM` 줄을 바꾼다.

```sh
docker buildx imagetools inspect alpine:3.24 | sed -n 3p
```

## 로컬 확인

파드 목록 JSON을 넣어 변환 결과만 본다.

```sh
docker run --rm -i --entrypoint jq reach-l1-collector:local \
  --arg cluster reused-prod --arg ns reused -f /app/inventory.jq < pods.json
```

운영 파드 목록은 cp 노드에서 `kubectl get pods -n reused -o json`으로 받는다. 이 JSON에는 파드 스펙 전체(환경 변수 포함)가 들어 있으니 저장소 밖 임시 폴더에 두고 확인 뒤 지운다.

환경 변수·토큰이 없을 때의 실패도 확인할 수 있다.

```sh
docker run --rm --read-only reach-l1-collector:local; echo "exit=$?"    # exit=2
docker run --rm --read-only -e NAMESPACES=reused -e CLUSTER=reused-prod -e REACH_URL=http://127.0.0.1:9 \
  reach-l1-collector:local; echo "exit=$?"                               # failed namespace=reused, exit=1
```

## 배포

- 이미지: ECR `logssey/reach-l1-collector`에 올리고 CronJob에서 digest로 고정한다.
- 매니페스트: `gitops`의 `reach/l1/`(서비스 계정, `reused` 네임스페이스 Role·RoleBinding, CronJob), 네임스페이스 `reach`.
- 즉시 실행: `kubectl -n reach create job --from=cronjob/reach-l1-collector reach-l1-manual-$(date +%s)`

## 현재 상태

대시보드의 수집 경로(`/internal/v1/reach/l1/workloads`)와 수집기 인증은 아직 구현 전이다. ECR 저장소와 `gitops` 매니페스트는 인프라 담당과 합의한 뒤 추가한다. 그 전까지는 로컬 확인까지만 할 수 있다.
