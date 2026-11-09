package com.logssey.reach.rule;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.rule.dto.ReachVulnFunctionPageResponse;
import com.logssey.reach.rule.dto.ReachVulnFunctionResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** API-10 취약 함수 데이터. 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional(readOnly = true)
public class ReachVulnFunctionService {

    static final int DEFAULT_SIZE = 20;
    static final int MAX_SIZE = 100;
    /** excluded는 명세에 있지만 지금 데이터에 뺀 메서드 기록이 없어 받기만 한다 */
    static final List<String> INCLUDES = List.of("total", "excluded");

    private final ReachVulnFunctionData data;
    private final ReachRuleRepository repository;

    public ReachVulnFunctionService(ReachVulnFunctionData data, ReachRuleRepository repository) {
        this.data = data;
        this.repository = repository;
    }

    public ReachVulnFunctionPageResponse vulnFunctions(String loginId, ReachVulnFunctionFilter filter,
                                                       Integer size, String cursor, List<String> include) {
        requireAdmin(loginId);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        var includes = ReachCodes.checked(include, INCLUDES);
        int fingerprint = Objects.hash(filter.fingerprint(), data.version(), data.generated());
        var after = cursor == null ? null : ReachDataCursor.decode(cursor);
        if (after != null && after.fingerprint() != fingerprint) throw new ApiException(ErrorCode.INVALID_INPUT);

        var matched = data.items().stream().filter(item -> matches(item, filter)).sorted(order(filter.sort())).toList();
        int from = after == null ? 0 : Math.min(after.offset(), matched.size());
        int to = Math.min(from + limit, matched.size());
        boolean hasNext = to < matched.size();
        return new ReachVulnFunctionPageResponse(matched.subList(from, to),
                hasNext ? new ReachDataCursor(to, fingerprint).encode() : null, hasNext,
                includes.contains("total") ? (long) matched.size() : null, data.version(), data.generated());
    }

    private static boolean matches(ReachVulnFunctionResponse item, ReachVulnFunctionFilter filter) {
        return (filter.cve().isEmpty() || filter.cve().contains(item.cve()))
                && (filter.packagePrefix() == null || item.packageUrl().startsWith(filter.packagePrefix()));
    }

    /** 고른 칸이 먼저, 나머지는 기본 순서 cve → class → method → id (명세 API-10 sort) */
    private static Comparator<ReachVulnFunctionResponse> order(String sort) {
        Comparator<ReachVulnFunctionResponse> byCve = (a, b) -> ReachVulnFunctionData.compareCve(a.cve(), b.cve());
        Comparator<ReachVulnFunctionResponse> byClass = Comparator.comparing(ReachVulnFunctionResponse::className);
        Comparator<ReachVulnFunctionResponse> byMethod = Comparator.comparing(ReachVulnFunctionResponse::method);
        Comparator<ReachVulnFunctionResponse> rest = byCve.thenComparing(byClass).thenComparing(byMethod)
                .thenComparingInt(ReachVulnFunctionResponse::id);
        return switch (sort) {
            case "class" -> byClass.thenComparing(rest);
            case "method" -> byMethod.thenComparing(rest);
            default -> rest;
        };
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        if (!repository.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
    }
}
