package com.logssey.reach.ci.auth;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachTestProperties;
import com.logssey.reach.ci.ReachCiCheckRequest;
import com.logssey.reach.ci.ReachTargetRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** CI 토큰이 할 수 있는 일 (11/02 결정 ③). 토큰 검증은 ReachCiOidcIntegrationTest */
class ReachCiAccessTest {

    private static final String COMMIT = "bb4639b".repeat(5) + "00000";
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static final ReachCiAccess ACCESS = new ReachCiAccess(ReachTestProperties.REUSED,
            new ReachCiProperties("Logssey", null, null));

    private static final ReachCiCaller PR_123 = caller("Logssey/service-backend", "pull_request", "refs/pull/123/merge");
    private static final ReachCiCaller MAIN = caller("Logssey/service-backend", "workflow_run", "refs/heads/main");

    @Test
    void pullRequestCheckFromThePullRequestEvent() {
        allowed(() -> ACCESS.authorizeCreate(PR_123, pr("service-backend", 123)));
        allowed(() -> ACCESS.authorizeCreate(PR_123, pr("Logssey/service-backend", 123)));   // 소유자를 붙여 와도 된다
        allowed(() -> ACCESS.authorizeCreate(PR_123, pr("SERVICE-BACKEND", 123)));           // 대소문자

        forbidden(() -> ACCESS.authorizeCreate(PR_123, pr("service-backend", null)));         // PR 번호 없음: 어느 PR인지 모른다
        forbidden(() -> ACCESS.authorizeCreate(PR_123, pr("service-backend", 124)));          // 다른 PR 번호
        forbidden(() -> ACCESS.authorizeCreate(caller("Logssey/service-backend", "push", "refs/heads/main"),
                pr("service-backend", 123)));                                                // PR 이벤트가 아님
        forbidden(() -> ACCESS.authorizeCreate(PR_123, pr("service-frontend", 123)));         // 본문 레포가 다름
        forbidden(() -> ACCESS.authorizeCreate(PR_123, pr("Other/service-backend", 123)));    // 소유자가 다름
        forbidden(() -> ACCESS.authorizeCreate(PR_123, new ReachCiCheckRequest("PR", "service-backend", COMMIT,
                null, repoTarget("service-frontend"), null, null, null)));                   // 대상 레포가 다름
        forbidden(() -> ACCESS.authorizeCreate(PR_123, new ReachCiCheckRequest("PR", "service-frontend", COMMIT,
                null, repoTarget("service-backend"), null, null, null)));                    // 본문 레포만 다름
        forbidden(() -> ACCESS.authorizeCreate(MAIN, new ReachCiCheckRequest("IMAGE_BUILD", "service-frontend",
                COMMIT, null, image("logssey/reused-api", null).target(), null, null, null))); // 이미지는 맞고 본문 레포만 다름
    }

    @Test
    void otherChecksOnlyFromTheDefaultBranch() {
        allowed(() -> ACCESS.authorizeCreate(MAIN, image("logssey/reused-api", null)));
        allowed(() -> ACCESS.authorizeCreate(MAIN, image("logssey/reused-chat", "CHAT")));   // 같은 레포의 다른 앱

        forbidden(() -> ACCESS.authorizeCreate(caller("Logssey/service-backend", "push", "refs/heads/develop"),
                image("logssey/reused-api", null)));
        forbidden(() -> ACCESS.authorizeCreate(PR_123, image("logssey/reused-api", null)));
        forbidden(() -> ACCESS.authorizeCreate(caller("Logssey/service-backend", "pull_request_target", "refs/heads/main"),
                image("logssey/reused-api", null)));                                         // ref는 기본 브랜치지만 PR이 계기
        forbidden(() -> ACCESS.authorizeCreate(MAIN, image("logssey/reused-web", null)));     // 다른 레포의 이미지
        forbidden(() -> ACCESS.authorizeCreate(MAIN, image("logssey/unknown", null)));        // 등록 안 된 이미지
        forbidden(() -> ACCESS.authorizeCreate(MAIN, image("logssey/reused-api", "WEB")));    // 다른 레포의 앱
        forbidden(() -> ACCESS.authorizeCreate(MAIN, new ReachCiCheckRequest("SCHEDULE", "service-backend", null,
                null, null, 7L, null, null)));                                               // 재검사는 사람만

        var develop = new ReachCiAccess(ReachTestProperties.REUSED, new ReachCiProperties("Logssey", "develop", null));
        allowed(() -> develop.authorizeCreate(caller("Logssey/service-backend", "push", "refs/heads/develop"),
                image("logssey/reused-api", null)));
    }

    @Test
    void onlyWatchedRepositoriesOfTheConfiguredOwner() {
        forbidden(() -> ACCESS.authorizeCreate(caller("Logssey/dashboard-backend", "pull_request", "refs/pull/1/merge"),
                pr("dashboard-backend", 1)));
        forbidden(() -> ACCESS.authorizeCreate(caller("Someone/service-backend", "pull_request", "refs/pull/1/merge"),
                pr("service-backend", 1)));
        forbidden(() -> ReachCiAccess.closed().authorizeCreate(PR_123, pr("service-backend", 123)));   // 조직 설정 없음
        forbidden(() -> new ReachCiAccess(ReachTestProperties.REUSED, new ReachCiProperties(" ", null, null))
                .authorizeCreate(PR_123, pr("service-backend", 123)));
    }

    @Test
    void resultsOnlyForTheRepositoryThatCreatedTheCheck() {
        allowed(() -> ACCESS.requireOwner(PR_123, owner("CI:Logssey/service-backend", "PR", "service-backend", 123)));
        allowed(() -> ACCESS.requireOwner(MAIN, owner("CI:logssey/Service-Backend", "IMAGE_BUILD", "service-backend")));

        forbidden(() -> ACCESS.requireOwner(PR_123, owner("CI:Logssey/service-frontend", "PR", "service-frontend", 123)));
        forbidden(() -> ACCESS.requireOwner(PR_123, owner("USER:1", "PR", "service-backend")));   // 사람이 만든 PR 검사
        assertThatThrownBy(() -> ACCESS.requireOwner(PR_123, Optional.empty()))
                .isInstanceOfSatisfying(ApiException.class, e -> org.assertj.core.api.Assertions
                        .assertThat(e.errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
        forbidden(() -> ReachCiAccess.closed().requireOwner(PR_123, owner("CI:Logssey/service-backend", "PR", null, 123)));
    }

    @Test
    void ciChecksOnlyTakeResultsFromTheSameKindOfRun() {
        // 같은 레포라도 만들 때와 같은 규칙: PR 토큰은 자기 PR 검사에만, 기본 브랜치 검사는 기본 브랜치 실행만
        var imageCheck = owner("CI:Logssey/service-backend", "IMAGE_BUILD", "service-backend");
        forbidden(() -> ACCESS.requireOwner(PR_123, imageCheck));                                 // PR 토큰이 운영 이미지 결과를 올림
        forbidden(() -> ACCESS.requireOwner(caller("Logssey/service-backend", "pull_request_target", "refs/heads/main"),
                imageCheck));
        forbidden(() -> ACCESS.requireOwner(caller("Logssey/service-backend", "workflow_run", "refs/heads/feature"),
                imageCheck));                                                                     // 기본 브랜치가 아님

        var prCheck = owner("CI:Logssey/service-backend", "PR", "service-backend", 123);
        forbidden(() -> ACCESS.requireOwner(caller("Logssey/service-backend", "pull_request", "refs/pull/124/merge"),
                prCheck));                                                                        // 다른 PR의 토큰
        forbidden(() -> ACCESS.requireOwner(MAIN, prCheck));                                      // PR 검사는 그 PR 실행만
        forbidden(() -> ACCESS.requireOwner(PR_123, owner("CI:Logssey/service-backend", "PR", "service-backend")));   // 번호 없는 옛 검사
    }

    @Test
    void onlyTheReachWorkflowOfTheRepository() {
        var ciYml = new ReachCiCaller("Logssey/service-backend", "repo:Logssey/service-backend:test", "workflow_run",
                "refs/heads/main", "Logssey/service-backend/.github/workflows/ci.yml@refs/heads/main");
        var otherRepo = new ReachCiCaller("Logssey/service-backend", "repo:Logssey/service-backend:test", "workflow_run",
                "refs/heads/main", "Logssey/service-frontend/.github/workflows/reach.yml@refs/heads/main");
        var none = new ReachCiCaller("Logssey/service-backend", "repo:Logssey/service-backend:test", "workflow_run",
                "refs/heads/main", null);
        var upperCase = new ReachCiCaller("Logssey/service-backend", "repo:Logssey/service-backend:test", "workflow_run",
                "refs/heads/main", "logssey/Service-Backend/.github/workflows/reach.yml@refs/heads/main");
        var imageCheck = owner("CI:Logssey/service-backend", "IMAGE_BUILD", "service-backend");

        for (var caller : new ReachCiCaller[] {ciYml, otherRepo, none}) {
            forbidden(() -> ACCESS.authorizeCreate(caller, image("logssey/reused-api", null)));   // 같은 레포의 다른 워크플로
            forbidden(() -> ACCESS.requireOwner(caller, imageCheck));
        }
        allowed(() -> ACCESS.authorizeCreate(upperCase, image("logssey/reused-api", null)));     // 레포 이름 대소문자
        forbidden(() -> ACCESS.requireOwner(new ReachCiCaller("Logssey/service-backend", "s", "workflow_dispatch",
                "refs/heads/main", "Logssey/service-backend/.github/workflows/ci.yml@refs/heads/main"),
                owner("USER:1", "MANUAL", "service-backend")));                                 // 대시보드 요청도 Reach 워크플로만
    }

    @Test
    void scanRequestedOnTheDashboardIsUploadedByTheDispatchedRunOfItsRepository() {
        var dispatched = caller("Logssey/service-backend", "workflow_dispatch", "refs/heads/main");
        allowed(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "MANUAL", "service-backend")));
        allowed(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "MANUAL", "Logssey/service-backend")));

        forbidden(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "MANUAL", "service-frontend")));   // 다른 레포의 스캔
        forbidden(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "MANUAL", null)));                 // 레포를 모르는 스캔
        forbidden(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "PR", "service-backend")));        // 사람이 만든 PR 검사
        forbidden(() -> ACCESS.requireOwner(caller("Logssey/service-backend", "workflow_dispatch", "refs/heads/feature"),
                owner("USER:1", "MANUAL", "service-backend")));                                          // 기본 브랜치가 아님
        forbidden(() -> ACCESS.requireOwner(MAIN, owner("USER:1", "MANUAL", "service-backend")));          // dispatch가 아님
        forbidden(() -> ACCESS.requireOwner(PR_123, owner("USER:1", "MANUAL", "service-backend")));
        forbidden(() -> ACCESS.requireOwner(caller("Logssey/dashboard-backend", "workflow_dispatch", "refs/heads/main"),
                owner("USER:1", "MANUAL", "dashboard-backend")));                                        // 감시 대상이 아닌 레포
    }

    @Test
    void dailyRescanOfTheDashboardIsUploadedByTheDispatchedRunOfItsRepository() {
        var dispatched = caller("Logssey/service-backend", "workflow_dispatch", "refs/heads/main");
        allowed(() -> ACCESS.requireOwner(dispatched, owner("SYSTEM", "SCHEDULE", "service-backend")));

        forbidden(() -> ACCESS.requireOwner(dispatched, owner("SYSTEM", "SCHEDULE", "service-frontend")));   // 다른 레포
        forbidden(() -> ACCESS.requireOwner(dispatched, owner("SYSTEM", "MANUAL", "service-backend")));      // 예약 작업은 SCHEDULE만
        forbidden(() -> ACCESS.requireOwner(dispatched, owner("USER:1", "SCHEDULE", "service-backend")));    // 사람이 만든 SCHEDULE 검사
        forbidden(() -> ACCESS.requireOwner(MAIN, owner("SYSTEM", "SCHEDULE", "service-backend")));          // dispatch가 아님
    }

    private static Optional<ReachCiAccess.CheckOwner> owner(String scope, String mode, String repository) {
        return owner(scope, mode, repository, null);
    }

    private static Optional<ReachCiAccess.CheckOwner> owner(String scope, String mode, String repository, Integer prNumber) {
        return Optional.of(new ReachCiAccess.CheckOwner(scope, mode, repository, prNumber));
    }

    /** 그 레포의 Reach 워크플로가 받은 토큰 */
    private static ReachCiCaller caller(String repository, String event, String ref) {
        return new ReachCiCaller(repository, "repo:" + repository + ":test", event, ref,
                repository + "/.github/workflows/reach.yml@" + ref);
    }

    private static ReachCiCheckRequest pr(String repository, Integer number) {
        var pr = number == null ? null : new ReachCiCheckRequest.PullRequest(number, "main", "feature");
        return new ReachCiCheckRequest("PR", repository, COMMIT, pr, repoTarget(repository), null, null, null);
    }

    private static ReachTargetRequest repoTarget(String name) {
        return new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo(name, COMMIT, null), null);
    }

    private static ReachCiCheckRequest image(String repository, String app) {
        return new ReachCiCheckRequest("IMAGE_BUILD", "service-backend", COMMIT, null,
                new ReachTargetRequest("IMAGE", app, null, new ReachTargetRequest.Image(repository, DIGEST)), null, null, null);
    }

    private static void allowed(Executable call) {
        assertThatCode(call::execute).doesNotThrowAnyException();
    }

    private static void forbidden(Executable call) {
        assertThatThrownBy(call::execute).isInstanceOfSatisfying(ApiException.class,
                e -> org.assertj.core.api.Assertions.assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
    }
}
