package com.logssey.reach.l1;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.l1.dto.ReachInventoryResponse;
import com.logssey.reach.l1.dto.ReachWorkloadPageResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach L1 워크로드 업로드(ADMIN 수동, 클러스터 수집기)와 Finding deployment 재계산 (Reach API 명세 2-2) */
@Service
@Transactional   // 쓰기라 readOnly가 아니다. 조회 행 덮어쓰기·워크로드 교체·재계산이 한 트랜잭션
public class ReachL1Service {

    /** 이 안의 조회만 믿는다. 하루 한 번 수집이 한 번 빠져도 UNKNOWN이 안 되게 */
    static final String FRESH = "48 hours";
    /** 명세에 없어 정한 것: 한 번에 받는 컨테이너 수 상한 */
    static final int MAX_CONTAINERS = 1000;
    /** 명세에 없어 정한 것: observedAt이 이만큼까지 미래인 것은 시계 차이로 보고 받는다 */
    static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");
    /** 목록 페이지 크기 (명세 2-4) */
    static final int DEFAULT_SIZE = 20;
    static final int MAX_SIZE = 100;

    private final ReachL1Repository repository;
    /** 수집 범위(logssey.reach.l1)와 앱 코드(logssey.reach.apps). PRD FR-15 */
    private final ReachProperties properties;
    private final String cluster;
    private final List<String> namespaces;
    private final String fresh;
    /** 설정의 이미지 저장소 → 앱 코드. 스캔 전 이미지의 앱을 API-07에 보여 준다 */
    private final Map<String, String> imageApps;

    @Autowired   // 생성자가 둘이라 Spring이 쓸 쪽을 표시한다. 없으면 기동 실패
    public ReachL1Service(ReachL1Repository repository, ReachProperties properties) {
        this(repository, properties, FRESH);
    }

    /**
     * 테스트용으로 fresh를 바꿀 수 있다. L1이 꺼져 있으면(cluster나 namespaces가 없음) 업로드는 400,
     * 목록은 빈 결과, 재계산은 하지 않는다. 빈 IN ()은 SQL 오류라 namespaces가 비면 묻지 않는다
     */
    ReachL1Service(ReachL1Repository repository, ReachProperties properties, String fresh) {
        this.repository = repository;
        this.properties = properties;
        boolean enabled = properties.l1().enabled();
        this.cluster = enabled ? properties.l1().cluster() : null;
        this.namespaces = enabled ? properties.l1().namespaces() : List.of();
        this.fresh = fresh;
        var images = new LinkedHashMap<String, String>();
        for (var app : properties.apps()) {
            if (app.image() != null) images.put(app.image(), app.code());
        }
        this.imageApps = Map.copyOf(images);
    }

    /** L1 수동 업로드(ADMIN 세션). 그 (cluster, namespace)의 워크로드를 통째로 바꾸고 deployment를 다시 계산한다 */
    public ReachInventoryResponse upload(String loginId, ReachInventoryRequest request) {
        long userId = requireAdmin(loginId);
        return save(request, "MANUAL", "USER:" + userId);
    }

    /**
     * 클러스터 수집기 업로드. 토큰(서명·발급자·aud·수집기 서비스 계정 sub)은 보안 체인이 검사한 뒤다.
     * 받는 범위와 검사는 수동 업로드와 같고, 기록에 수집기 토큰의 sub를 남긴다
     */
    public ReachInventoryResponse uploadFromCollector(String subject, ReachInventoryRequest request) {
        if (subject == null || subject.isBlank()) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return save(request, "CLUSTER_READER", subject);
    }

    private ReachInventoryResponse save(ReachInventoryRequest request, String source, String reportedBy) {
        validate(request);
        repository.lockRecompute();   // Finding을 고치기 전에 잡는다. 재계산하는 쪽이 모두 같은 순서라 교착이 없다
        // 저장된 것보다 오래된 조회는 거절한다(늦게 온 재시도가 최신 상태를 되돌리지 않게). 같은 시각은 받는다
        if (repository.saveObservation(request.cluster(), request.namespace(), request.observedAt(),
                source, reportedBy) == 0) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.deleteWorkloads(request.cluster(), request.namespace());
        for (var workload : request.workloads()) {
            for (var container : workload.containers()) {
                repository.insertWorkload(request.cluster(), request.namespace(), workload.kind(), workload.name(),
                        container.name(), container.image(), container.imageDigest(), container.readyReplicas());
            }
        }
        int updated = recomputeScope(null);
        return new ReachInventoryResponse(request.cluster(), request.namespace(), request.observedAt(),
                request.workloads().size(), updated);
    }

    /**
     * API-07 워크로드 목록. 저장된 조회 결과를 주고 클러스터를 직접 조회하지 않는다.
     * 허용한 (cluster, namespace)만 본다. namespace 필터가 허용 목록과 겹치지 않으면 400이 아니라 빈 결과다.
     * 조회 기록이 없어도 503이 아니라 빈 observations·items로 200이다
     */
    @Transactional(readOnly = true)
    public ReachWorkloadPageResponse workloads(String loginId, ReachWorkloadFilter filter,
                                               Integer size, String cursor, String include) {
        requireAdmin(loginId);
        ReachCodes.checked(filter.app(), properties.codes());   // 설정에 없는 앱 코드는 400
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (include != null && !include.equals("total")) throw new ApiException(ErrorCode.INVALID_INPUT);
        var after = cursor == null ? null : ReachWorkloadCursor.decode(cursor);
        if (after != null && after.filter() != filter.fingerprint()) throw new ApiException(ErrorCode.INVALID_INPUT);

        var scope = filter.namespace().isEmpty() ? namespaces
                : namespaces.stream().filter(filter.namespace()::contains).toList();
        Long total = "total".equals(include) ? 0L : null;
        if (scope.isEmpty()) {   // 빈 IN ()은 SQL 오류라 묻지 않는다
            return new ReachWorkloadPageResponse(List.of(), List.of(), null, false, total);
        }

        var rows = repository.workloads(cluster, scope, fresh, imageApps, filter, after, limit + 1);   // 하나 더 가져와 다음 페이지 확인
        boolean hasNext = rows.size() > limit;
        var page = hasNext ? rows.subList(0, limit) : rows;
        String nextCursor = null;
        if (hasNext) {
            var last = page.get(page.size() - 1);
            nextCursor = new ReachWorkloadCursor(last.namespace(), last.name(), last.kind(), last.container(),
                    last.image().digest(), filter.fingerprint()).encode();
        }
        if (total != null) {
            total = repository.countWorkloads(cluster, scope, fresh, imageApps, filter);
        }
        return new ReachWorkloadPageResponse(repository.observations(cluster, scope, fresh), page,
                nextCursor, hasNext, total);
    }

    /**
     * Finding deployment만 다시 계산한다(6시간마다 작업, API-13 업로드 끝). targetId가 null이면 모든 이미지 대상.
     * 업로드가 없어도 조회가 48시간을 넘기면 RUNNING·NOT_RUNNING이 UNKNOWN으로 바뀌어야 한다(PRD FR-04).
     * 부르는 쪽 트랜잭션에 합류하므로, 잠금은 그 트랜잭션이 끝날 때 풀린다. 바뀐 Finding 수를 돌려준다
     */
    public int recompute(Long targetId) {
        repository.lockRecompute();
        return recomputeScope(targetId);
    }

    /** L1이 꺼져 있으면 바꿀 것이 없다 (deployment는 기본값 UNKNOWN 그대로) */
    private int recomputeScope(Long targetId) {
        return namespaces.isEmpty() ? 0 : repository.recompute(cluster, namespaces, fresh, targetId);
    }

    /**
     * 재계산 잠금만 잡는다. reach_findings를 고치는 다른 쪽(API-13 결과 업로드)이 Finding을 건드리기 전에 부른다.
     * 정기 작업은 잠금 → Finding 순서라, 반대 순서로 잡으면 서로 기다리다 교착한다. 부르는 트랜잭션이 끝나면 풀린다
     */
    public void lockRecompute() {
        repository.lockRecompute();
    }

    /**
     * 빈 workloads·containers는 받는다(파드가 없는 네임스페이스, 이미지를 아직 못 받은 컨테이너).
     * 길이는 V42 칸 길이다. 넘기면 DB에서 500이 나니 여기서 400으로 막는다
     */
    private void validate(ReachInventoryRequest request) {
        if (request == null || cluster == null || !cluster.equals(request.cluster()) || !in(request.namespace(), namespaces)
                || request.observedAt() == null || request.observedAt().isAfter(OffsetDateTime.now().plus(CLOCK_SKEW))
                || request.workloads() == null) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        int containers = 0;
        var seen = new HashSet<String>();
        for (var workload : request.workloads()) {
            if (workload == null || badText(workload.kind(), 30) || badText(workload.name(), 253)
                    || workload.containers() == null) {
                throw new ApiException(ErrorCode.INVALID_INPUT);
            }
            for (var container : workload.containers()) {
                if (container == null || badText(container.name(), 253) || badText(container.image(), 512)
                        || container.imageDigest() == null || !DIGEST.matcher(container.imageDigest()).matches()
                        || container.readyReplicas() == null || container.readyReplicas() < 0
                        // 같은 워크로드·컨테이너·digest가 두 번이면 uq_reach_workloads에서 500이 난다
                        || !seen.add(workload.kind() + "\n" + workload.name() + "\n" + container.name() + "\n" + container.imageDigest())
                        || ++containers > MAX_CONTAINERS) {
                    throw new ApiException(ErrorCode.INVALID_INPUT);
                }
            }
        }
    }

    /** List.of(...).contains(null)은 NullPointerException이라 null을 먼저 거른다 */
    private static boolean in(String value, List<String> allowed) {
        return value != null && allowed.contains(value);
    }

    /** DB VARCHAR 길이는 글자(code point) 수라 Java length()(UTF-16 단위)가 아니라 codePointCount로 센다 */
    private static boolean badText(String value, int max) {
        return value == null || value.isBlank() || value.codePointCount(0, value.length()) > max;
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
