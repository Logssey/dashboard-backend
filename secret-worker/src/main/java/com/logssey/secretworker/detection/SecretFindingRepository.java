package com.logssey.secretworker.detection;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;

/** Persists only normalized metadata and keyed digests, within one transaction per source object. */
public final class SecretFindingRepository {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final SecretFindingNormalizer normalizer;

    public SecretFindingRepository(JdbcTemplate jdbc, TransactionTemplate transactions,
                                   SecretFindingNormalizer normalizer) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.transactions = Objects.requireNonNull(transactions);
        this.normalizer = Objects.requireNonNull(normalizer);
    }

    public long beginGitleaksRun(long runScopeId, String engineVersion, String configHash, Instant now) {
        if (runScopeId <= 0 || engineVersion == null || !engineVersion.matches("[A-Za-z0-9_.-]{1,100}")
                || configHash == null || !configHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("INVALID_TOOL_RUN");
        }
        try {
            return Objects.requireNonNull(transactions.execute(transaction ->
                    startOrRestartToolRun(runScopeId, engineVersion, configHash, now)));
        } catch (DataAccessException error) {
            throw new IllegalStateException("TOOL_RUN_PERSISTENCE_FAILED");
        }
    }

    private long startOrRestartToolRun(long runScopeId, String engineVersion, String configHash, Instant now) {
        List<ExistingToolRun> existing = jdbc.query("""
                SELECT tr.tool_run_id, tr.engine_version, tr.config_hash, rs.run_id, rs.scope_id,tr.fingerprint_key_version,tr.scope_origin_version,sc.response_origin_version AS current_origin_version
                FROM secret_tool_runs tr
                JOIN secret_run_scopes rs ON rs.run_scope_id = tr.run_scope_id
                JOIN secret_connection_scopes sc ON sc.scope_id=rs.scope_id
                WHERE tr.run_scope_id = ? AND tr.engine = 'GITLEAKS'
                FOR UPDATE OF tr
                """, (rs, row) -> new ExistingToolRun(rs.getLong("tool_run_id"),
                rs.getString("engine_version"), rs.getString("config_hash"),
                rs.getLong("run_id"), rs.getLong("scope_id"),rs.getString("fingerprint_key_version"),rs.getObject("scope_origin_version",Long.class),rs.getLong("current_origin_version")), runScopeId);
        if (existing.isEmpty()) {
            Long id = jdbc.queryForObject("""
                    INSERT INTO secret_tool_runs
                        (run_scope_id, engine, engine_version, config_hash, status, started_at,fingerprint_key_version,scope_origin_version)
                    SELECT ?, 'GITLEAKS', ?, ?, 'RUNNING', ?,?,s.response_origin_version FROM secret_run_scopes rs
                    JOIN secret_connection_scopes s ON s.scope_id=rs.scope_id WHERE rs.run_scope_id=?
                    RETURNING tool_run_id
                    """, Long.class, runScopeId, engineVersion, configHash, utc(now),normalizer.keyVersion(),runScopeId);
            return Objects.requireNonNull(id);
        }
        ExistingToolRun old = existing.getFirst();
        if (!old.engineVersion().equals(engineVersion) || !old.configHash().equals(configHash)
            || old.fingerprintVersion()!=null&&!old.fingerprintVersion().equals(normalizer.keyVersion())
            || old.originVersion()!=null&&old.originVersion()!=old.currentOriginVersion()) {
            throw new IllegalStateException("TOOL_RUN_CONFIG_CHANGED");
        }
        // A leased job may restart after partial ingestion. Prior findings are not fresh evidence
        // for the new attempt; occurrence presence becomes UNKNOWN until seen again.
        jdbc.update("""
                UPDATE secret_occurrences o SET presence_status = 'UNKNOWN'
                WHERE o.last_seen_run_id = ? AND o.scope_id = ?
                  AND EXISTS (SELECT 1 FROM secret_findings f
                              WHERE f.occurrence_id = o.occurrence_id AND f.tool_run_id = ?)
                  AND NOT EXISTS (SELECT 1 FROM secret_findings f
                                  WHERE f.occurrence_id = o.occurrence_id AND f.run_id = ?
                                    AND f.tool_run_id <> ?)
                """, old.runId(), old.scopeId(), old.id(), old.runId(), old.id());
        jdbc.update("DELETE FROM secret_findings WHERE tool_run_id = ?", old.id());
        jdbc.update("""
                UPDATE secret_tool_runs SET status = 'RUNNING', finding_count = 0,
                    started_at = ?, finished_at = NULL, failure_code = NULL,fingerprint_key_version=?,scope_origin_version=?
                WHERE tool_run_id = ?
                """, utc(now),normalizer.keyVersion(),old.currentOriginVersion(), old.id());
        return old.id();
    }

    public ObjectResult recordObject(long toolRunId, String sourceObjectRef, String objectVersion,
                                     byte[] utf8Content, GitleaksScanResult scan, Instant now) {
        if (toolRunId <= 0 || sourceObjectRef == null || sourceObjectRef.isBlank()
                || sourceObjectRef.length() > 500 || objectVersion != null && objectVersion.length() > 200
                || scan == null || now == null) {
            throw new IllegalArgumentException("INVALID_DETECTION_OBJECT");
        }
        try {
            return transactions.execute(status -> persistObject(toolRunId, sourceObjectRef, objectVersion,
                    utf8Content, null, scan, now));
        } catch (DataAccessException error) {
            throw new IllegalStateException("SECRET_PERSISTENCE_FAILED");
        }
    }

    /** Reuses a single in-memory inspection for persistence and validation handoff. */
    public ObjectResult recordInspection(long toolRunId, String sourceObjectRef, String objectVersion,
                                         SecretFindingNormalizer.Inspection inspection,
                                         GitleaksScanResult scan, Instant now) {
        return recordInspection(toolRunId, sourceObjectRef, objectVersion, inspection, scan, now,
                com.logssey.secret.run.progress.core.ScanExecutionObserver.NONE);
    }

    public ObjectResult recordInspection(long toolRunId, String sourceObjectRef, String objectVersion,
                                         SecretFindingNormalizer.Inspection inspection,
                                         GitleaksScanResult scan, Instant now,
                                         com.logssey.secret.run.progress.core.ScanExecutionObserver observer) {
        if (toolRunId <= 0 || sourceObjectRef == null || sourceObjectRef.isBlank()
                || sourceObjectRef.length() > 500 || objectVersion != null && objectVersion.length() > 200
                || inspection == null || scan == null || now == null) {
            throw new IllegalArgumentException("INVALID_DETECTION_OBJECT");
        }
        try {
            return transactions.execute(status -> {
                long started = System.nanoTime();
                var result = persistObject(toolRunId, sourceObjectRef, objectVersion, null, inspection, scan, now);
                observer.record(com.logssey.secret.run.progress.core.ScanExecutionObserver.Stage.DETECTION,
                        com.logssey.secret.run.progress.core.ScanExecutionObserver.Operation.FINDINGS_COMMIT,
                        com.logssey.secret.run.progress.core.ScanExecutionObserver.Outcome.COMPLETED,
                        null, null, (long) result.credentialCount(), null,
                        com.logssey.secret.run.progress.core.ScanExecutionObserver.elapsed(started));
                return result;
            });
        } catch (DataAccessException error) {
            throw new IllegalStateException("SECRET_PERSISTENCE_FAILED");
        }
    }

    public void finishToolRun(long toolRunId, String status, String failureCode, Instant now) {
        if (toolRunId <= 0 || !List.of("SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED").contains(status)
                || failureCode != null && !failureCode.matches("[A-Z0-9_]{1,80}")) {
            throw new IllegalArgumentException("INVALID_TOOL_RUN_RESULT");
        }
        try {
            int changed = jdbc.update("""
                    UPDATE secret_tool_runs SET status = ?, failure_code = ?, finished_at = ?,
                        finding_count = (SELECT count(*) FROM secret_findings WHERE tool_run_id = ?)
                    WHERE tool_run_id = ?
                    """, status, failureCode, utc(now), toolRunId, toolRunId);
            if (changed != 1) throw new IllegalStateException("TOOL_RUN_NOT_FOUND");
        } catch (DataAccessException error) {
            throw new IllegalStateException("TOOL_RUN_PERSISTENCE_FAILED");
        }
    }

    private ObjectResult persistObject(long toolRunId, String sourceObjectRef, String objectVersion,
                                       byte[] content, SecretFindingNormalizer.Inspection supplied,
                                       GitleaksScanResult scan, Instant now) {
        ToolContext context = jdbc.query("""
                SELECT sr.run_id, sr.connection_id, rs.scope_id, tr.engine_version, tr.config_hash, tr.status
                FROM secret_tool_runs tr
                JOIN secret_run_scopes rs ON rs.run_scope_id = tr.run_scope_id
                JOIN secret_scan_runs sr ON sr.run_id = rs.run_id
                JOIN secret_connection_scopes sc ON sc.scope_id = rs.scope_id
                    AND sc.connection_id = sr.connection_id
                WHERE tr.tool_run_id = ? AND tr.engine = 'GITLEAKS'
                """, (rs, row) -> new ToolContext(rs.getLong("run_id"), rs.getLong("connection_id"),
                rs.getLong("scope_id"), rs.getString("engine_version"), rs.getString("config_hash"),
                rs.getString("status")), toolRunId).stream().findFirst()
                .orElseThrow(() -> new IllegalArgumentException("TOOL_RUN_SCOPE_MISMATCH"));
        if (!"RUNNING".equals(context.status()) || !context.engineVersion().equals(scan.engineVersion())
                || !context.configHash().equals(scan.configHash())) {
            throw new IllegalArgumentException("TOOL_RUN_RESULT_MISMATCH");
        }
        SecretFindingNormalizer.Inspection inspection = supplied == null
                ? normalizer.inspect(context.connectionId(), sourceObjectRef, content, scan.findings()) : supplied;
        if (inspection.connectionId() != context.connectionId()
                || !inspection.sourceObjectRef().equals(sourceObjectRef)
                || !inspection.detectorFindings().equals(scan.findings())) {
            throw new IllegalArgumentException("INSPECTION_SCOPE_MISMATCH");
        }
        List<SecretFindingNormalizer.Credential> normalized = inspection.credentials();
        int storedFindings = 0;
        for (SecretFindingNormalizer.Credential credential : normalized) {
            long credentialSetId = upsertCredential(credential, context.runId(), now);
            if (credential.awsKeyIdFingerprint() != null)
                jdbc.update("UPDATE secret_credential_sets SET aws_key_id_fingerprint=? WHERE credential_set_id=? AND fingerprint_key_version=?",
                        credential.awsKeyIdFingerprint(), credentialSetId, credential.fingerprintKeyVersion());
            long occurrenceId = upsertOccurrence(credentialSetId, context, sourceObjectRef,
                    credential.locationKey(), objectVersion, now);
            for (GitleaksFinding finding : credential.findings()) {
                storedFindings += jdbc.update("""
                        INSERT INTO secret_findings
                            (occurrence_id, run_id, tool_run_id, finding_key, rule_id, rule_version, detected_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (tool_run_id, finding_key) DO NOTHING
                        """, occurrenceId, context.runId(), toolRunId,
                        findingKey(sourceObjectRef, finding), finding.ruleId(),
                        scan.engineVersion() + ":" + scan.configHash(), utc(now));
            }
        }
        return new ObjectResult(normalized.size(), storedFindings);
    }

    private long upsertCredential(SecretFindingNormalizer.Credential credential, long runId, Instant now) {
        if("CONFIRMED".equals(credential.componentState())) {
            jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)",Object.class,ByteBuffer.wrap(credential.fingerprint()).getLong());
            boolean existing=Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS(SELECT 1 FROM secret_credential_sets WHERE component_state='CONFIRMED' AND issuer=? AND credential_type=? AND fingerprint_key_version=? AND fingerprint=?)
                """,Boolean.class,credential.issuer(),credential.credentialType(),credential.fingerprintKeyVersion(),credential.fingerprint()));
            if(!existing&&!credential.promotionLocators().isEmpty()) {
                var args=new java.util.ArrayList<Object>(List.of(credential.issuer(),credential.credentialType(),credential.fingerprintKeyVersion()));
                args.addAll(credential.promotionLocators());
                var matches=jdbc.queryForList("SELECT credential_set_id FROM secret_credential_sets WHERE component_state='CANDIDATE' AND issuer=? AND credential_type=? AND fingerprint_key_version=? AND candidate_locator IN ("
                    +String.join(",",java.util.Collections.nCopies(credential.promotionLocators().size(),"?"))+") ORDER BY first_seen_at,credential_set_id LIMIT 1 FOR UPDATE",Long.class,args.toArray());
                if(!matches.isEmpty()) {
                    long id=matches.getFirst();
                    jdbc.update("UPDATE secret_credential_sets SET component_state='CONFIRMED',fingerprint=?,candidate_locator=NULL,masked_label=?,last_seen_at=greatest(last_seen_at,?) WHERE credential_set_id=?",
                        credential.fingerprint(),credential.maskedLabel(),utc(now),id);
                    return id;
                }
            }
        }
        String conflict = "CONFIRMED".equals(credential.componentState()) ? """
                ON CONFLICT (issuer, credential_type, fingerprint_key_version, fingerprint)
                    WHERE component_state = 'CONFIRMED'
                DO UPDATE SET last_seen_at = GREATEST(secret_credential_sets.last_seen_at, EXCLUDED.last_seen_at)
                """ : """
                ON CONFLICT (fingerprint_key_version, candidate_locator)
                    WHERE component_state = 'CANDIDATE'
                DO UPDATE SET last_seen_at = GREATEST(secret_credential_sets.last_seen_at, EXCLUDED.last_seen_at)
                """;
        Long id = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, candidate_locator,
                     fingerprint_key_version, masked_label, first_seen_at, last_seen_at, first_seen_run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """ + conflict + " RETURNING credential_set_id", Long.class,
                credential.issuer(), credential.credentialType(), credential.componentState(),
                credential.fingerprint(), credential.candidateLocator(), credential.fingerprintKeyVersion(),
                credential.maskedLabel(), utc(now), utc(now), runId);
        return Objects.requireNonNull(id);
    }

    private long upsertOccurrence(long credentialSetId, ToolContext context, String sourceRef,
                                  String locationKey, String objectVersion, Instant now) {
        Long id = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     latest_object_version, environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at, last_seen_run_id)
                VALUES (?, ?, ?, ?, ?, ?, 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'PRESENT', ?, ?, ?)
                ON CONFLICT (credential_set_id, connection_id, source_object_ref, location_key)
                DO UPDATE SET latest_object_version = EXCLUDED.latest_object_version,
                    last_seen_at = GREATEST(secret_occurrences.last_seen_at, EXCLUDED.last_seen_at),
                    last_seen_run_id = EXCLUDED.last_seen_run_id,
                    presence_status = 'PRESENT'
                RETURNING occurrence_id
                """, Long.class, credentialSetId, context.connectionId(), context.scopeId(), sourceRef,
                locationKey, objectVersion, utc(now), utc(now), context.runId());
        return Objects.requireNonNull(id);
    }

    private static String findingKey(String sourceRef, GitleaksFinding finding) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, sourceRef);
            update(digest, finding.ruleId());
            for (int position : new int[]{finding.startLine(), finding.endLine(),
                    finding.startColumn(), finding.endColumn()}) {
                digest.update(ByteBuffer.allocate(4).putInt(position).array());
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("FINDING_KEY_UNAVAILABLE");
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static OffsetDateTime utc(Instant instant) {
        return Objects.requireNonNull(instant).atOffset(ZoneOffset.UTC);
    }

    private record ToolContext(long runId, long connectionId, long scopeId,
                               String engineVersion, String configHash, String status) { }
    private record ExistingToolRun(long id, String engineVersion, String configHash,
                                   long runId, long scopeId,String fingerprintVersion,Long originVersion,long currentOriginVersion) { }
    public record ObjectResult(int credentialCount, int newFindingCount) { }
}
