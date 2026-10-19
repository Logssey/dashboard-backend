package com.logssey.iacworker.analysis;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.zip.GZIPInputStream;

import com.logssey.iacworker.ClaimedIacJob;
import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProcessor;

import org.neo4j.driver.exceptions.Neo4jException;
import software.amazon.awssdk.core.exception.SdkException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * ANALYZE_RUN: PR 의 plan 을 그래프 사본에 반영해 경로 변화와 판정을 저장한다.
 * Neo4j·IAM 시뮬레이터 호출은 임대 잠금 밖에서 하고, 저장만 persistIfLeased 안에서 한다.
 */
public class AnalyzeRunProcessor implements IacJobProcessor {

    private final GraphLoader loader;
    private final AnalysisEngine engine;
    private final AnalyzeRunRepository repository;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public AnalyzeRunProcessor(GraphLoader loader, AnalysisEngine engine, AnalyzeRunRepository repository) {
        this.loader = loader;
        this.engine = engine;
        this.repository = repository;
    }

    @Override
    public IacJobKind kind() {
        return IacJobKind.ANALYZE_RUN;
    }

    @Override
    public void process(ClaimedIacJob job, IacJobExecutionService execution) {
        long runId = Objects.requireNonNull(job.runId(), "ANALYZE_RUN needs a run");
        if (!"ANALYZING".equals(repository.runStatus(runId).orElse(null))) {
            // 새 커밋으로 SUPERSEDED 되었거나 이미 끝난 run: 할 일이 없다
            return;
        }
        JsonNode plan = parse(repository.plan(runId).orElseThrow(() -> new IacJobFailure(IacJobFailureCode.PLAN_MISSING, false)));

        AnalysisEngine.Result result;
        try {
            result = engine.analyze(loader.load(), plan);
        } catch (Neo4jException e) {
            throw new IacJobFailure(IacJobFailureCode.GRAPH_UNAVAILABLE, true);
        } catch (SdkException e) {
            throw new IacJobFailure(IacJobFailureCode.SIMULATOR_UNAVAILABLE, true);
        }

        long added = result.changes().stream().filter(c -> c.change().equals("ADDED")).count();
        var removed = result.changes().stream().filter(c -> c.change().equals("REMOVED")).toList();
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("resources", result.resources());
        stats.put("paths", Map.of("added", added, "removed", removed.size(),
                // 같은 자격 증명(역할)으로 이어지는 경로들을 한 갈래로 센다 (화면의 "경로 −N")
                "removedRoutes", removed.stream().map(AnalysisEngine.Change::roleId).filter(Objects::nonNull)
                        .distinct().count()));
        stats.put("verdict", result.verdict());

        boolean written = execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            repository.clearChanges(runId);
            for (var change : result.changes()) {
                repository.insertChange(runId, change, mapper.writeValueAsString(change.hops()),
                        mapper.writeValueAsString(change.evidence()));
            }
            repository.finishRun(runId, result.verdict(), result.highestSeverity(), repository.graphAsOf());
            String json = mapper.writeValueAsString(stats);
            repository.jobStats(job.jobId(), json);
            repository.audit(runId, json);
        });
        if (!written) {
            throw new IacJobFailure(IacJobFailureCode.LEASE_EXPIRED, true);
        }
    }

    private JsonNode parse(byte[] gzip) {
        try (var in = new GZIPInputStream(new ByteArrayInputStream(gzip))) {
            return mapper.readTree(in);
        } catch (IOException | JacksonException e) {
            throw new IacJobFailure(IacJobFailureCode.PLAN_INVALID, false);
        }
    }
}
