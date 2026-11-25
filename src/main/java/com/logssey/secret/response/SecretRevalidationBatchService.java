package com.logssey.secret.response;

import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.command.SecretCommandResult;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Reserves compatible location checks together and keeps each reservation's receipt. */
@Service
public class SecretRevalidationBatchService {
    public record Item(Long occurrenceId, Long expectedOccurrenceVersion) { }
    public record Request(Long expectedCaseVersion, String idempotencyKey, List<Item> items) { }

    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretLocationWorkflow workflow;
    private final SecretLocationReadiness readiness;
    private final SecretRevalidationRepository repository;
    private final SecretCommandExecutor commands;
    private final SecretReadSnapshots snapshots;

    public SecretRevalidationBatchService(JdbcTemplate jdbc, SecretAccessService access,
            SecretLocationWorkflow workflow, SecretLocationReadiness readiness,
            SecretRevalidationRepository repository, SecretCommandExecutor commands,
            SecretReadSnapshots snapshots) {
        this.jdbc = jdbc;
        this.access = access;
        this.workflow = workflow;
        this.readiness = readiness;
        this.repository = repository;
        this.commands = commands;
        this.snapshots = snapshots;
    }

    public Map<String, Object> request(long caseId, Request request, String login) {
        validate(request);
        var actor = access.requirePrincipal(login);
        var command = commands.execute(actor, SecretCommandExecutor.Kind.LOCATION_REVALIDATE_BATCH,
                request.idempotencyKey(), digest(caseId + ":" + request),
                () -> requireVisible(actor, caseId), () -> reserve(actor, caseId, request));
        return receipt(actor, caseId, command.targetId());
    }

    private SecretCommandResult reserve(SecretPrincipal actor, long caseId, Request request) {
        var current = workflow.lockCase(caseId);
        long version = ((Number) current.get("version")).longValue();
        SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(), version);
        // The case lock orders competing batches. Connection locks are then acquired in ID order.
        jdbc.queryForList("""
                SELECT c.connection_id FROM secret_connections c
                WHERE EXISTS(SELECT 1 FROM secret_occurrences o
                  JOIN secret_case_occurrences co USING(occurrence_id)
                  WHERE co.case_id=? AND o.connection_id=c.connection_id)
                ORDER BY c.connection_id FOR UPDATE OF c
                """, caseId);
        var prepared = request.items().stream().map(item -> prepare(actor, caseId, item)).toList();
        long batchId = jdbc.queryForObject("""
                INSERT INTO secret_revalidation_batches(case_id,requested_by_user_id,case_version)
                VALUES(?,?,?) RETURNING batch_id
                """, Long.class, caseId, actor.userId(), version);
        for (int index = 0; index < prepared.size(); index++) {
            var item = prepared.get(index);
            Long revalidationId = null;
            if (item.error() == null) {
                String key = "B" + HexFormat.of().formatHex(digest(batchId + ":" + item.occurrenceId()));
                var result = repository.reserve(item.target(), item.action(), item.baseline(),
                        actor.userId(), key, version);
                version++;
                revalidationId = result.revalidationId();
                jdbc.update("""
                        INSERT INTO secret_location_activities(case_id,occurrence_id,activity_type,
                          actor_user_id,case_version,occurrence_version,reference_id)
                        VALUES(?,?,'REVALIDATION_REQUESTED',?,?,?,?)
                        """, caseId, item.occurrenceId(), actor.userId(), version,
                        item.target().occurrenceVersion() + 1, revalidationId);
                snapshots.invalidateOccurrence(item.occurrenceId());
            }
            jdbc.update("""
                    INSERT INTO secret_revalidation_batch_items(batch_id,ordinal,occurrence_id,
                      revalidation_id,error_code,reason_code) VALUES(?,?,?,?,?,?)
                    """, batchId, index, item.occurrenceId(), revalidationId,
                    item.error() == null ? null : item.error().name(), item.reason());
        }
        jdbc.update("UPDATE secret_revalidation_batches SET case_version=? WHERE batch_id=?", version, batchId);
        return new SecretCommandResult(batchId, version, SecretCommandResult.Status.PENDING);
    }

    private Prepared prepare(SecretPrincipal actor, long caseId, Item item) {
        if (!workflow.assignedRemediator(actor, caseId, item.occurrenceId()))
            return Prepared.failure(item.occurrenceId(), ErrorCode.FORBIDDEN, "LOCATION_ASSIGNEE_REQUIRED");
        var target = repository.lockTarget(caseId, item.occurrenceId()).orElse(null);
        if (target == null) return Prepared.failure(item.occurrenceId(), ErrorCode.NOT_FOUND, "NO_CURRENT_CASE");
        if (item.expectedOccurrenceVersion() != target.occurrenceVersion())
            return Prepared.failure(item.occurrenceId(), ErrorCode.CONFLICT, "STALE_OCCURRENCE_VERSION");
        var capability = readiness.capabilities(actor, caseId, item.occurrenceId());
        if (!Boolean.TRUE.equals(capability.get("canRequestRevalidation")))
            return Prepared.failure(item.occurrenceId(), ErrorCode.CONFLICT,
                    (String) capability.get("revalidationBlockReasonCode"));
        var action = repository.latestAction(caseId, item.occurrenceId()).orElse(null);
        if (action == null) return Prepared.failure(item.occurrenceId(), ErrorCode.CONFLICT, "COMPLETE_ACTIONS_REQUIRED");
        var baseline = repository.baseline(item.occurrenceId())
                .orElse(new SecretRevalidationRepository.Baseline(null, null));
        return new Prepared(item.occurrenceId(), target, action, baseline, null, null);
    }

    private Map<String, Object> receipt(SecretPrincipal actor, long caseId, long batchId) {
        var allowed = workflow.visibleLocations(caseId, actor).stream()
                .map(value -> ((Number) value.get("occurrence_id")).longValue())
                .collect(java.util.stream.Collectors.toSet());
        var reservations = repository.list(caseId).stream().collect(java.util.stream.Collectors.toMap(
                SecretRevalidationResult::revalidationId, value -> value));
        var rows = jdbc.queryForList("SELECT * FROM secret_revalidation_batch_items WHERE batch_id=? ORDER BY ordinal", batchId);
        var items = new ArrayList<Map<String, Object>>();
        for (var row : rows) {
            long occurrence = ((Number) row.get("occurrence_id")).longValue();
            Long id = (Long) row.get("revalidation_id");
            if (id != null && allowed.contains(occurrence)) {
                var result = reservations.get(id);
                long connection = jdbc.queryForObject("SELECT connection_id FROM secret_occurrences WHERE occurrence_id=?", Long.class, occurrence);
                items.add(facts("occurrenceId", occurrence, "status", "PENDING", "result",
                        result.withRunAccess(access.canReadConnectionFacts(actor, connection))));
            } else {
                items.add(facts("occurrenceId", occurrence, "status", "FAILED", "errorCode",
                        id != null ? "FORBIDDEN" : row.get("error_code"), "reasonCode",
                        id != null ? "LOCATION_ASSIGNEE_REQUIRED" : row.get("reason_code")));
            }
        }
        long accepted = items.stream().filter(item -> "PENDING".equals(item.get("status"))).count();
        return facts("batchId", batchId, "items", items, "acceptedCount", accepted,
                "failedCount", items.size() - accepted, "caseVersion",
                jdbc.queryForObject("SELECT case_version FROM secret_revalidation_batches WHERE batch_id=?", Long.class, batchId),
                "requiresSnapshotRefresh", true);
    }

    private void requireVisible(SecretPrincipal actor, long caseId) {
        if (workflow.visibleLocations(caseId, actor).isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
    }

    private static void validate(Request request) {
        if (request == null || request.expectedCaseVersion() == null || request.expectedCaseVersion() < 0
                || request.items() == null || request.items().isEmpty() || request.items().size() > 100)
            throw new ApiException(ErrorCode.INVALID_INPUT);
        var ids = new HashSet<Long>();
        for (var item : request.items()) {
            if (item == null || item.occurrenceId() == null || item.occurrenceId() <= 0
                    || item.expectedOccurrenceVersion() == null || item.expectedOccurrenceVersion() < 0
                    || !ids.add(item.occurrenceId())) throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }

    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private record Prepared(long occurrenceId, SecretRevalidationRepository.Target target,
            SecretRevalidationRepository.Action action, SecretRevalidationRepository.Baseline baseline,
            ErrorCode error, String reason) {
        static Prepared failure(long occurrence, ErrorCode code, String reason) {
            return new Prepared(occurrence, null, null, null, code, reason);
        }
    }
}
