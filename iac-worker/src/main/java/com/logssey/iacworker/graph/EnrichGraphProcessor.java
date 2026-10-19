package com.logssey.iacworker.graph;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.logssey.iacworker.ClaimedIacJob;
import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProcessor;

import org.neo4j.driver.exceptions.Neo4jException;
import software.amazon.awssdk.core.exception.SdkException;
import tools.jackson.databind.json.JsonMapper;

/**
 * ENRICH_GRAPH: 매일 수집 뒤 그래프를 보강하고 열린 경로(iac_attack_paths)를 다시 계산한다.
 * Neo4j·AWS 호출은 임대 잠금 밖에서 하고, 결과 저장만 persistIfLeased 안에서 한다.
 */
public class EnrichGraphProcessor implements IacJobProcessor {

    private static final Map<Integer, String> SEVERITY_BY_TIER = Map.of(1, "CRITICAL", 2, "HIGH", 3, "MEDIUM");

    private final GraphEnricher enricher;
    private final CloudFrontOrigins origins;
    private final NodeAddresses nodeAddresses;
    private final AttackPathRepository repository;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public EnrichGraphProcessor(GraphEnricher enricher, CloudFrontOrigins origins, NodeAddresses nodeAddresses,
                                AttackPathRepository repository) {
        this.enricher = enricher;
        this.origins = origins;
        this.nodeAddresses = nodeAddresses;
        this.repository = repository;
    }

    @Override
    public IacJobKind kind() {
        return IacJobKind.ENRICH_GRAPH;
    }

    @Override
    public void process(ClaimedIacJob job, IacJobExecutionService execution) {
        List<CloudFrontOrigins.Origin> cloudFront;
        try {
            cloudFront = origins.list();
        } catch (SdkException e) {
            throw new IacJobFailure(IacJobFailureCode.AWS_UNAVAILABLE, true);
        }
        GraphEnricher.Stats stats;
        List<GraphEnricher.FoundPath> paths;
        try {
            stats = enricher.enrich(job.jobId(), repository.dataAssets(), cloudFront, nodeAddresses.byNodeName());
            paths = enricher.openPaths();
        } catch (Neo4jException e) {
            throw new IacJobFailure(IacJobFailureCode.GRAPH_UNAVAILABLE, true);
        }

        Map<String, GraphEnricher.FoundPath> byFingerprint = new LinkedHashMap<>();
        for (var path : paths) {
            byFingerprint.putIfAbsent(fingerprint(path), path);
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("openPaths", byFingerprint.size());
        summary.put("tier1Paths", byFingerprint.values().stream().filter(p -> p.tier() == 1).count());
        summary.put("reach", stats.reach());
        summary.put("origin", stats.origin());
        summary.put("credentials", stats.credentials());
        summary.put("instances", stats.instances());
        summary.put("tiered", stats.tiered());
        summary.put("removedEdges", stats.removed());

        boolean written = execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            for (var entry : byFingerprint.entrySet()) {
                var path = entry.getValue();
                repository.upsertOpen(entry.getKey(), mapper.writeValueAsString(path.hops()), path.hops().size() - 1,
                        path.dataAssetId(), path.tier(), SEVERITY_BY_TIER.get(path.tier()), job.jobId());
            }
            summary.put("closedPaths", repository.closeNotSeenBy(job.jobId()));
            repository.audit(job.jobId(), mapper.writeValueAsString(summary));
        });
        if (!written) {
            throw new IacJobFailure(IacJobFailureCode.LEASE_EXPIRED, true);
        }
    }

    /** 시작 + 거쳐 가는 노드 + 대상. 같은 경로면 실행이 달라도 같은 값이다. */
    static String fingerprint(GraphEnricher.FoundPath path) {
        String key = path.hops().stream().map(GraphEnricher.Hop::id).collect(Collectors.joining("\n"));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
