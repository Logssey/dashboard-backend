package com.logssey.reach.ci.auth;

import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.ci.ReachCiCheckRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * CI 토큰이 할 수 있는 일 (11/02 결정 ③). 어긋나면 모두 403 FORBIDDEN.
 * - 토큰 레포가 이 설치의 감시 대상(조직 + logssey.reach.apps의 레포)이어야 한다
 * - 본문·대상의 레포가 토큰 레포와 같아야 한다. 이미지 대상은 그 레포 앱의 이미지여야 한다
 * - PR 검사는 pull_request 이벤트에서만, 그 밖의 검사는 기본 브랜치 ref에서만
 * - 재검사(rescanOf)는 사람만 한다
 * - 결과 조회·업로드는 그 검사를 만든 레포의 토큰만
 */
@Component
public class ReachCiAccess {

    private final ReachProperties apps;
    private final ReachCiProperties ci;

    @Autowired
    public ReachCiAccess(ReachProperties apps, ReachCiProperties ci) {
        this.apps = apps;
        this.ci = ci;
    }

    /** CI 설정 없이 만든 서비스용(테스트). CI 토큰은 모두 거부한다 */
    public static ReachCiAccess closed() {
        return new ReachCiAccess(new ReachProperties(null, null), ReachCiProperties.closed());
    }

    /** API-12 실행. 본문 형식 검사(400) 뒤에 부른다 */
    public void authorizeCreate(ReachCiCaller caller, ReachCiCheckRequest request) {
        requireAllowedRepository(caller);
        if (!sameRepository(caller, request.repository()) || request.rescanOf() != null) throw forbidden();

        var target = request.target();
        if (target != null) {
            if (target.repo() != null && !sameRepository(caller, target.repo().name())) throw forbidden();
            if (target.image() != null && !imageOf(caller, target.image().repository())) throw forbidden();
            if (target.app() != null && !appOf(caller, target.app())) throw forbidden();
        }

        boolean allowedEvent = "PR".equals(request.mode())
                ? "pull_request".equals(caller.eventName()) && samePullRequest(caller, request.pullRequest())
                : ("refs/heads/" + ci.defaultBranch()).equals(caller.ref());
        if (!allowedEvent) throw forbidden();
    }

    /** API-12 결과 조회, API-13. scope는 검사의 idempotency_scope(검사가 없으면 빈 값 → 404) */
    public void requireOwner(ReachCiCaller caller, Optional<String> scope) {
        requireAllowedRepository(caller);
        String owner = scope.orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!owner.equalsIgnoreCase(caller.scope())) throw forbidden();
    }

    private void requireAllowedRepository(ReachCiCaller caller) {
        if (!ci.open() || !caller.repositoryOwner().equalsIgnoreCase(ci.repositoryOwner())) throw forbidden();
        boolean watched = apps.apps().stream()
                .anyMatch(app -> app.repo() != null && name(app.repo()).equalsIgnoreCase(caller.repositoryName()));
        if (!watched) throw forbidden();
    }

    /** 러너는 레포 이름만(service-backend) 보낸다. 소유자를 붙여 오면 소유자까지 같아야 한다 */
    private static boolean sameRepository(ReachCiCaller caller, String value) {
        if (value == null) return false;
        return value.contains("/") ? value.equalsIgnoreCase(caller.repository())
                : value.equalsIgnoreCase(caller.repositoryName());
    }

    private boolean imageOf(ReachCiCaller caller, String image) {
        return apps.apps().stream().anyMatch(app -> image != null && image.equals(app.image())
                && app.repo() != null && name(app.repo()).equalsIgnoreCase(caller.repositoryName()));
    }

    private boolean appOf(ReachCiCaller caller, String code) {
        return apps.apps().stream().anyMatch(app -> code.equalsIgnoreCase(app.code())
                && app.repo() != null && name(app.repo()).equalsIgnoreCase(caller.repositoryName()));
    }

    /** pull_request 이벤트의 ref는 refs/pull/<번호>/merge다. 본문이 다른 PR 번호를 대지 못하게 한다 */
    private static boolean samePullRequest(ReachCiCaller caller, ReachCiCheckRequest.PullRequest pr) {
        return pr == null || pr.number() == null || ("refs/pull/" + pr.number() + "/merge").equals(caller.ref());
    }

    private static String name(String repo) {
        return repo.substring(repo.lastIndexOf('/') + 1);
    }

    private static ApiException forbidden() {
        return new ApiException(ErrorCode.FORBIDDEN);
    }
}
