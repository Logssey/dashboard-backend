package com.logssey.reach.ci;

/**
 * 스캔 대상 (API 명세 API-01 target, API-12 target). type이 REPO면 repo, IMAGE면 image를 채운다.
 * 값 검사는 ReachTargets가 한다 (record 생성자에서 던지면 Jackson이 다른 예외로 감싼다)
 */
public record ReachTargetRequest(String type, String app, Repo repo, Image image) {

    /** commit은 40자 SHA. path는 레포 안 하위 경로 (chat은 chat-server) */
    public record Repo(String name, String commit, String path) {}

    /** 태그는 받지 않고 digest만 받는다. repository에는 레지스트리 호스트를 넣지 않는다 (명세 3-2) */
    public record Image(String repository, String digest) {}
}
