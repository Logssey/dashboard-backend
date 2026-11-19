package com.logssey.iac.run;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * CI 가 plan 전 검사(gate) 결과와 함께 run 을 등록한다 (API 계약 POST /runs).
 * prTitle 은 PR 제목 (선택, 256자까지. 제어 문자는 공백으로 바꿔 저장).
 * trigger 는 PR(기본, prNumber 필수) 또는 PUSH(main 의 매일 refresh plan, prNumber 없음 → 드리프트 점검).
 */
public record IacRunRequest(
        @NotNull @Pattern(regexp = "^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$") String repo,
        @Positive Integer prNumber,
        @NotNull @Pattern(regexp = "^[0-9a-f]{40}$") String headSha,
        @NotNull @Valid Gate gate,
        @Pattern(regexp = "^(PR|PUSH)$") String trigger,
        @Size(max = 256) String prTitle) {

    public IacRunRequest(String repo, Integer prNumber, String headSha, Gate gate) {
        this(repo, prNumber, headSha, gate, "PR", null);
    }

    public IacRunRequest(String repo, Integer prNumber, String headSha, Gate gate, String trigger) {
        this(repo, prNumber, headSha, gate, trigger, null);
    }

    public boolean isPush() {
        return "PUSH".equals(trigger);
    }

    public record Gate(
            @NotNull @Pattern(regexp = "^(PASSED|BLOCKED)$") String status,
            @NotNull @Size(max = 200) List<@Valid Finding> findings) {
    }

    /** policy/gate.sh 의 GATE_FINDINGS 한 줄과 같은 모양. */
    public record Finding(
            @NotNull @Pattern(regexp = "^(block|warn)$") String level,
            @NotNull @Size(min = 1, max = 500) String msg) {
    }
}
