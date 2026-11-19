package com.logssey.iac.query;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * S-01 E plan 전 검사. 관문별로 main 기준 열린 위반과 최근 7일 PR 차단 수.
 * supplyChain 은 버전 미고정·모듈 내용 변경 같은 공급망 경고의 열린 건수.
 */
public record IacGatesResponse(OffsetDateTime mainCheckedAt, List<Stage> stages, SupplyChain supplyChain) {

    public record Stage(String stage, String name, List<String> ruleIds, long mainOpen, long prBlocked7d) {
    }

    public record SupplyChain(long unpinnedProviders, long unpinnedModules, long changedModules, long lockChanges) {
    }
}
