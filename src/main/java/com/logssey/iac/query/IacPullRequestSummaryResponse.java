package com.logssey.iac.query;

import java.time.OffsetDateTime;

/**
 * S-01 D: PR 별 최신 run 한 줄. PR 이 열렸는지·닫혔는지는 GitHub 정보라 아직 모른다 (최근 run 순).
 * title 은 그 run 을 등록할 때 iac-report 가 보낸 PR 제목 (없으면 null).
 * reason 은 가장 높은 결과의 규칙 ID (화면이 문구를 만든다).
 */
public record IacPullRequestSummaryResponse(int number, String title, long runId, String headSha, String status, String verdict,
                                            String highestSeverity, OffsetDateTime checkedAt, int pathsAdded,
                                            int pathsRemoved, int removedRoutes, boolean stateReaderIncrease,
                                            String reason) {
}
