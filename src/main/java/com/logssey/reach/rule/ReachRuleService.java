package com.logssey.reach.rule;

import java.util.List;
import java.util.Objects;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.rule.dto.ReachRulePageResponse;
import com.logssey.reach.rule.dto.ReachRuleResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** API-09 규칙 조회. 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional(readOnly = true)
public class ReachRuleService {

    static final List<String> LIST_INCLUDES = List.of("total", "definition");
    static final List<String> DETAIL_INCLUDES = List.of("definition");

    private final ReachRuleData data;
    private final ReachRuleRepository repository;

    public ReachRuleService(ReachRuleData data, ReachRuleRepository repository) {
        this.data = data;
        this.repository = repository;
    }

    public ReachRulePageResponse rules(String loginId, ReachRuleFilter filter, Integer size, String cursor, List<String> include) {
        requireAdmin(loginId);
        int limit = size == null ? ReachVulnFunctionService.DEFAULT_SIZE : size;
        if (limit < 1 || limit > ReachVulnFunctionService.MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        var includes = ReachCodes.checked(include, LIST_INCLUDES);
        int fingerprint = Objects.hash(filter.fingerprint(), data.version());
        var after = cursor == null ? null : ReachDataCursor.decode(cursor);
        if (after != null && after.fingerprint() != fingerprint) throw new ApiException(ErrorCode.INVALID_INPUT);

        var matched = data.rules().stream().filter(rule -> matches(rule, filter))
                .sorted((a, b) -> ReachVulnFunctionData.compareCve(a.cve(), b.cve())).toList();
        int from = after == null ? 0 : Math.min(after.offset(), matched.size());
        int to = Math.min(from + limit, matched.size());
        boolean hasNext = to < matched.size();
        var items = matched.subList(from, to).stream()
                .map(rule -> includes.contains("definition") ? rule : rule.withoutDefinition()).toList();
        return new ReachRulePageResponse(items, hasNext ? new ReachDataCursor(to, fingerprint).encode() : null, hasNext,
                includes.contains("total") ? (long) matched.size() : null, data.version());
    }

    /** 없는 ruleId면 404 */
    public ReachRuleResponse rule(String loginId, String ruleId, List<String> include) {
        requireAdmin(loginId);
        var includes = ReachCodes.checked(include, DETAIL_INCLUDES);
        var rule = data.rule(ruleId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return includes.contains("definition") ? rule : rule.withoutDefinition();
    }

    private static boolean matches(ReachRuleResponse rule, ReachRuleFilter filter) {
        return (filter.cve().isEmpty() || filter.cve().contains(rule.cve()))
                && (filter.packagePrefix() == null || rule.packages().stream().anyMatch(p -> p.startsWith(filter.packagePrefix())))
                && (filter.fact() == null || rule.facts().contains(filter.fact()));
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        if (!repository.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
    }
}
