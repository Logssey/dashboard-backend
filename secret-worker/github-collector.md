# GitHub 수집기 계약

`GitHubCollector`는 워커에서 호출하는 읽기 전용 어댑터다. 아직 예약 작업 실행기나 탐지 도구에 자동 연결하지 않는다. 연결을 붙일 때 `secret_connection_scopes.approved_ref`를 `GitHubApprovedScope.fromApprovedRef`로 해석하고 `history_limit=CURRENT_COMMIT_ONLY`만 전달한다. 예를 들어 `github://Logssey/test-find-key/main/fixtures/`는 해당 저장소의 `main` 현재 커밋에서 `fixtures/` 하위만 읽는다. 슬래시가 들어간 브랜치명은 URI의 브랜치 구간에서 `%2F`로 인코딩한다.

App ID, 설치 ID와 PEM 파일 **경로**는 워커의 보호된 실행 설정에서 `GitHubAppCredentials`로 전달한다. PEM 값이나 설치 토큰은 DB, 작업 페이로드, 일반 로그에 저장하지 않는다. 이 어댑터는 JWT로 저장소 하나와 `contents:read` 권한만 요청한다. GitHub API가 돌려준 URL을 따라가지 않고 고정 REST 경로에서 ref → commit → tree → blob 순서로 읽는다.

파일 내용은 `ContentSink.accept`가 호출된 동안에만 소비한다. 콜백은 동기적으로 처리해야 하며 호출이 끝나면 수집기가 바이트 배열을 지운다. 반환 `Result`에는 커밋, 경로, blob SHA, 바이트 수, 누락 사유만 있다. 처리할 수 없는 바이너리, symlink, submodule, LFS 포인터, 크기 제한, 권한 거부, API 실패와 절단된 트리는 명시적 누락으로 남긴다. 누락이 있는데 읽은 파일이 없으면 `FAILED`, 일부를 읽었으면 `PARTIAL`이다. 승인 폴더가 없으면 정상 0건으로 간주하지 않는다.

현재 구현은 한 브랜치의 현재 커밋에 있는 저장소 파일만 지원한다. 과거 커밋, Actions 실행 로그·아티팩트, 저장된 GitHub Secrets 값은 범위 밖이다. `GitHubCollectionLimits.DEFAULT`는 최대 1,000개 파일, 20,000개 트리 항목, 파일당 1 MiB, 전체 16 MiB를 적용한다. 초과 범위도 결과에 누락으로 남긴다.

로컬 HTTP 서버와 생성한 RSA 테스트 키로 동작을 검증한다. 실제 GitHub App 키나 저장소 파일을 테스트에서 읽지 않는다.

```powershell
.\gradlew.bat :secret-worker:test --tests 'com.logssey.secretworker.github.*'
```
