package com.logssey.reach.ci;

import java.util.Locale;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;

/** 요청의 target 검사와 정리. API-12와 API-01이 같이 쓴다 */
final class ReachTargets {

    private static final Pattern COMMIT = Pattern.compile("[0-9a-f]{40}");
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    /** V34 reach_targets의 이름·경로 칸 길이 */
    private static final int NAME_MAX = 200;

    /** 검사를 마친 대상. commit·digest는 소문자로 맞춘다 */
    record Resolved(String type, String app, String repoName, String repoPath, String repoCommit,
                    String imageRepository, String imageDigest, String displayName) {}

    /**
     * 형식이 틀리면 400, 형식은 맞는데 어느 서비스(app)인지 모르면 422.
     * 명세의 422는 TARGET_UNRESOLVED지만 공통 ErrorCode에 없어 같은 상태 코드의 UNPROCESSABLE을 쓴다
     */
    static Resolved resolve(ReachTargetRequest target) {
        if (target == null || target.type() == null) throw invalid();
        if (target.app() != null && !ReachCodes.APPS.contains(target.app())) throw invalid();
        return switch (target.type()) {
            case "REPO" -> repo(target);
            case "IMAGE" -> image(target);
            default -> throw invalid();
        };
    }

    /** 커밋 SHA 40자. 대문자로 와도 소문자로 맞춘다 */
    static String commit(String value) {
        String commit = value == null ? null : value.toLowerCase(Locale.ROOT);
        if (commit == null || !COMMIT.matcher(commit).matches()) throw invalid();
        return commit;
    }

    private static Resolved repo(ReachTargetRequest target) {
        var repo = target.repo();
        if (repo == null || target.image() != null || !name(repo.name())) throw invalid();
        String path = repo.path() == null || repo.path().isBlank() ? null : repo.path();
        if (path != null && !name(path)) throw invalid();
        String commit = commit(repo.commit());
        String app = target.app() != null ? target.app() : repoApp(repo.name(), path);
        String display = repo.name() + (path == null ? "" : "/" + path) + " @ " + commit.substring(0, 7);
        return new Resolved("REPO", app, repo.name(), path, commit, null, null, display);
    }

    private static Resolved image(ReachTargetRequest target) {
        var image = target.image();
        if (image == null || target.repo() != null || !name(image.repository())) throw invalid();
        // 태그(:)나 digest(@)를 붙인 값, 레지스트리 호스트(포트의 :)는 받지 않는다
        if (image.repository().contains(":") || image.repository().contains("@")) throw invalid();
        String digest = image.digest() == null ? null : image.digest().toLowerCase(Locale.ROOT);
        if (digest == null || !DIGEST.matcher(digest).matches()) throw invalid();
        String app = target.app() != null ? target.app() : imageApp(image.repository());
        String display = last(image.repository()) + " @ " + digest.substring("sha256:".length(), "sha256:".length() + 8);
        return new Resolved("IMAGE", app, null, null, null, image.repository(), digest, display);
    }

    /** app을 안 주면 레포·이미지 저장소 이름으로 정한다 (명세 3-2 표). 표에 없으면 422 */
    private static String repoApp(String name, String path) {
        return switch (last(name)) {
            case "service-backend" -> "chat-server".equals(path) ? "CHAT" : "API";
            case "service-frontend" -> "WEB";
            default -> throw new ApiException(ErrorCode.UNPROCESSABLE);
        };
    }

    private static String imageApp(String repository) {
        return switch (repository) {
            case "logssey/reused-api" -> "API";
            case "logssey/reused-web" -> "WEB";
            case "logssey/reused-chat" -> "CHAT";
            default -> throw new ApiException(ErrorCode.UNPROCESSABLE);
        };
    }

    /** Logssey/service-backend처럼 소유자를 붙여 와도 레포 이름으로 본다 */
    private static String last(String name) {
        return name.substring(name.lastIndexOf('/') + 1);
    }

    private static boolean name(String value) {
        return value != null && !value.isBlank() && value.length() <= NAME_MAX;
    }

    private static ApiException invalid() {
        return new ApiException(ErrorCode.INVALID_INPUT);
    }

    private ReachTargets() {}
}
