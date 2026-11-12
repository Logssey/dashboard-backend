package com.logssey.secretworker.notion;

import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;

import com.logssey.secret.notion.SecretNotionSourceCredentials;
import com.logssey.secretworker.*;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.DetectionFailure;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.*;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcTemplate;

/** Executes the common queue against explicitly approved current-page text scopes. */
public final class NotionSecretJobProcessor implements SecretJobProcessor {
  private final JdbcTemplate jdbc;
  private final NotionCollector collector;
  private final SecretNotionSourceCredentials credentials;
  private final SecretContentDetector detector;
  private final SecretFindingRepository findings;
  private final SecretFindingNormalizer normalizer;
  private final SecretValidationAttemptRepository attempts;
  private final AwsValidationService aws;
  private final GitHubPatValidator github;
  private final NotionTokenValidator notion;
  private final SecretJobProperties jobs;

  public NotionSecretJobProcessor(
      JdbcTemplate jdbc,
      NotionCollector collector,
      SecretNotionSourceCredentials credentials,
      SecretContentDetector detector,
      SecretFindingRepository findings,
      SecretFindingNormalizer normalizer,
      SecretValidationAttemptRepository attempts,
      AwsValidationService aws,
      GitHubPatValidator github,
      NotionTokenValidator notion,
      SecretJobProperties jobs) {
    this.jdbc = jdbc;
    this.collector = collector;
    this.credentials = credentials;
    this.detector = detector;
    this.findings = findings;
    this.normalizer = normalizer;
    this.attempts = attempts;
    this.aws = aws;
    this.github = github;
    this.notion = notion;
    this.jobs = jobs;
  }

  @Override
  public String provider() {
    return "NOTION";
  }

  @Override
  public void process(ClaimedSecretJob job, SecretJobExecutionService execution) {
    var heartbeat =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofVirtual().name("notion-job-lease").factory());
    var lost = new AtomicBoolean();
    long period = Math.max(1_000, jobs.leaseDuration().toMillis() / 3);
    var renewal =
        heartbeat.scheduleWithFixedDelay(
            () -> {
              try {
                if (!execution.renewLease(job.jobId(), job.leaseToken())) lost.set(true);
              } catch (RuntimeException ignored) {
                lost.set(true);
              }
            },
            period,
            period,
            TimeUnit.MILLISECONDS);
    long deadline = System.nanoTime() + Duration.ofMinutes(5).toNanos();
    try {
      if (attempts.isManual(job)) {
        revalidate(job, execution, lost, deadline);
      } else {
        scan(job, execution, lost, deadline);
      }
    } finally {
      renewal.cancel(true);
      heartbeat.shutdownNow();
    }
  }

  private void revalidate(
      ClaimedSecretJob job,
      SecretJobExecutionService execution,
      AtomicBoolean lost,
      long deadline) {
    new CredentialRevalidationProcessor(jdbc, normalizer, detector, attempts, aws, github, notion)
        .process(
            job,
            execution,
            (target, sink) -> {
              var scope =
                  NotionApprovedScope.fromApprovedRef(
                      (String) target.get("approved_ref"), (String) target.get("history_limit"));
              long scopeId = ((Number) target.get("scope_id")).longValue();
              var delivered = new AtomicBoolean();
              var result =
                  collector.collect(
                      scope,
                      NotionCollectionLimits.DEFAULT,
                      (source, bytes) -> {
                        check(job, scopeId, execution, lost, deadline, false);
                        if (source.nextRetryAt() != null)
                          waitUntil(job, source.nextRetryAt(), source.failureCode(), execution);
                        if (source.comparable()
                            && source.sourceObjectRef().equals(target.get("source_object_ref"))) {
                          sink.accept(source.sourceObjectRef(), source.version(), bytes);
                          delivered.set(true);
                        }
                      },
                      () -> check(job, scopeId, execution, lost, deadline));
              if (result.nextRetryAt() != null) {
                waitUntil(job, result.nextRetryAt(), result.failureCode(), execution);
                throw new SecretJobFailure(SecretJobFailureCode.SOURCE_RATE_LIMITED, true);
              }
              return result.comparable() && delivered.get();
            });
  }

  private void scan(
      ClaimedSecretJob job,
      SecretJobExecutionService execution,
      AtomicBoolean lost,
      long deadline) {
    List<Scope> scopes =
        jdbc.query(
            """
            SELECT rs.run_scope_id,s.scope_id,s.approved_ref,s.history_limit
            FROM secret_run_scopes rs JOIN secret_scan_runs r USING(run_id)
            JOIN secret_connection_scopes s ON s.scope_id=rs.scope_id AND s.connection_id=r.connection_id
            JOIN secret_connections c ON c.connection_id=r.connection_id
            WHERE r.run_id=? AND r.job_id=? AND r.connection_id=? AND c.provider='NOTION'
            ORDER BY rs.run_scope_id
            """,
            (rs, row) -> new Scope(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4)),
            job.runId(),
            job.jobId(),
            job.connectionId());
    if (scopes.isEmpty() || scopes.size() > 100)
      throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
    persist(
        job,
        execution,
        () ->
            jdbc.update(
                "UPDATE secret_scan_runs SET collection_status='RUNNING',"
                    + "detection_status='RUNNING',validation_status='RUNNING' WHERE run_id=?",
                job.runId()));
    var validation = new ValidationProgress();
    int usable = 0;
    boolean collectionPartial = false, detectionPartial = false;
    String failure = null;
    for (Scope scope : scopes) {
      check(job, scope.scopeId(), execution, lost, deadline);
      int failuresBefore = validation.failed;
      ScopeResult result = scanScope(job, scope, execution, lost, deadline, validation);
      if (result.objects() > 0) usable++;
      collectionPartial |= !"SUCCEEDED".equals(result.collection());
      detectionPartial |= !"SUCCEEDED".equals(result.detection());
      if (failure == null) failure = result.failure();
      if (!execution.recordScopeEvidence(
          job.jobId(), job.leaseToken(), scope.runScopeId(), validation.failed > failuresBefore))
        throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
      if (currentWait() != null) {
        throw new SecretJobFailure(SecretJobFailureCode.SOURCE_RATE_LIMITED, true);
      }
    }
    String collection = usable == 0 ? "FAILED" : collectionPartial ? "PARTIAL" : "SUCCEEDED";
    String detection = usable == 0 ? "FAILED" : detectionPartial ? "PARTIAL" : "SUCCEEDED";
    String reason = failure;
    persist(
        job,
        execution,
        () ->
            jdbc.update(
                "UPDATE secret_scan_runs SET collection_status=?,"
                    + "detection_status=?,validation_status=?,failure_code=? WHERE run_id=?",
                collection,
                detection,
                validation.status(),
                reason,
                job.runId()));
    if (usable == 0) throw new SecretJobFailure(failureCode(failure), retryable(failure));
    if (attempts.hasRetryable(job))
      throw new SecretJobFailure(SecretJobFailureCode.VALIDATOR_TEMPORARY, true);
  }

  private ScopeResult scanScope(
      ClaimedSecretJob job,
      Scope scope,
      SecretJobExecutionService execution,
      AtomicBoolean lost,
      long deadline,
      ValidationProgress validation) {
    NotionApprovedScope approved;
    try {
      approved = NotionApprovedScope.fromApprovedRef(scope.reference(), scope.history());
    } catch (IllegalArgumentException ignored) {
      finishScope(job, scope, execution, "FAILED", 0, 0, "INVALID_APPROVED_SCOPE");
      return new ScopeResult("FAILED", "FAILED", 0, "INVALID_APPROVED_SCOPE");
    }
    persist(
        job,
        execution,
        () ->
            jdbc.update(
                "UPDATE secret_run_scopes SET collection_status='RUNNING',"
                    + "started_at=clock_timestamp(),finished_at=NULL,object_count=NULL,failure_code=NULL,excluded_object_count=0"
                    + " WHERE run_scope_id=?",
                scope.runScopeId()));
    var toolId = new AtomicLong();
    persist(
        job,
        execution,
        () ->
            toolId.set(
                findings.beginGitleaksRun(
                    scope.runScopeId(),
                    detector.engineVersion(),
                    detector.configHash(),
                    Instant.now())));
    long tool = toolId.get();
    var objects = new AtomicInteger();
    var unattributed = new AtomicBoolean();
    String collection = "FAILED", detection = "FAILED", failure = null;
    int excluded = 0;
    try {
      var result =
          collector.observed(execution.observer(job, scope.runScopeId())).collect(
              approved,
              NotionCollectionLimits.DEFAULT,
              (source, bytes) -> {
                check(job, scope.scopeId(), execution, lost, deadline, false);
                if (source.nextRetryAt() != null)
                  waitUntil(job, source.nextRetryAt(), source.failureCode(), execution);
                var scan = execution.observer(job, scope.runScopeId()).measure(
                                    Stage.DETECTION, Operation.GITLEAKS_SCAN, () -> detector.scan(bytes));
                var inspection =
                    execution.observer(job, scope.runScopeId()).measure(
                                    Stage.DETECTION, Operation.CANDIDATE_NORMALIZATION, () -> normalizer.inspect(
                        job.connectionId(), source.sourceObjectRef(), bytes, scan.findings()));
                persist(
                    job,
                    execution,
                    () ->
                        findings.recordInspection(
                            tool,
                            source.sourceObjectRef(),
                            source.version(),
                            inspection,
                            scan,
                            Instant.now(), execution.observer(job, scope.runScopeId())));
                objects.incrementAndGet();
                var accounted = new HashSet<com.logssey.secretworker.detector.GitleaksFinding>();
                inspection.credentials().forEach(c -> accounted.addAll(c.findings()));
                if (!accounted.containsAll(scan.findings())) unattributed.set(true);
                validate(
                    job,
                    scope,
                    source,
                    inspection,
                    validation,
                    () -> check(job, scope.scopeId(), execution, lost, deadline, false));
              },
              () -> check(job, scope.scopeId(), execution, lost, deadline));
      if (result.nextRetryAt() != null)
        waitUntil(job, result.nextRetryAt(), result.failureCode(), execution);
      collection = result.status().name();
      detection =
          objects.get() == 0
              ? "FAILED"
              : result.comparable() && !unattributed.get() ? "SUCCEEDED" : "PARTIAL";
      failure = result.failureCode();
      if (failure == null && unattributed.get()) failure = "DETECTOR_NORMALIZATION_INCOMPLETE";
      excluded = result.excludedBlockCount();
      if ("SUCCEEDED".equals(collection) && objects.get() > 0) {
        // Notion only reports whether the page is published to the web. Record that as the
        // location's exposure range; it is not severity evidence and adds no ACCESS_SCOPE row.
        String range = result.publishedToWeb() ? "BROAD" : "BOUNDED";
        persist(job, execution, () -> recordExposureRange(tool, range));
      }
    } catch (SecretJobFailure error) {
      throw error;
    } catch (NotionSourceException error) {
      failure = "NOTION_" + error.code().name();
      if (error.retryAt() != null) waitUntil(job, error.retryAt(), failure, execution);
    } catch (DetectionFailure error) {
      failure = "DETECTOR_" + error.code().name();
      detection = objects.get() > 0 ? "PARTIAL" : "FAILED";
      collection = objects.get() > 0 ? "PARTIAL" : "FAILED";
    } catch (RuntimeException ignored) {
      failure = "RESULT_PERSISTENCE_FAILED";
      collection = objects.get() > 0 ? "PARTIAL" : "FAILED";
      detection = collection;
    }
    String toolStatus = detection;
    String code = failure;
    persist(job, execution, () -> findings.finishToolRun(tool, toolStatus, code, Instant.now()));
    finishScope(job, scope, execution, collection, objects.get(), excluded, failure);
    return new ScopeResult(collection, detection, objects.get(), failure);
  }

  private void validate(
      ClaimedSecretJob job,
      Scope scope,
      NotionCollector.Source source,
      SecretFindingNormalizer.Inspection inspection,
      ValidationProgress progress,
      Runnable beforeValidation) {
    for (var candidate : inspection.awsCandidates()) {
      beforeValidation.run();
      if (!progress.first(candidate.credential(), scope.runScopeId())) continue;
      observe(
          progress,
          scope.runScopeId(),
          candidate.credential(),
          () -> {
            var result =
                attempts.validateAws(
                    job,
                    candidate.credential(),
                    candidate.material(),
                    false,
                    aws,
                    scope.runScopeId(),
                    source.sourceObjectRef(),
                    source.version());
            return new CredentialValidationResult(
                result.status().name(), result.reason().name(), result.checkedAt(), null, null);
          });
    }
    for (var candidate : inspection.githubCandidates()) {
      beforeValidation.run();
      if (!progress.first(candidate.credential(), scope.runScopeId())) continue;
      observe(
          progress,
          scope.runScopeId(),
          candidate.credential(),
          () ->
              attempts.validateGitHub(
                  job,
                  candidate,
                  github,
                  scope.runScopeId(),
                  source.sourceObjectRef(),
                  source.version()));
    }
    for (var candidate : inspection.notionCandidates()) {
      beforeValidation.run();
      if (!progress.first(candidate.credential(), scope.runScopeId())) continue;
      // The common send boundary also observes this source connection's cooldown.
      observe(
          progress,
          scope.runScopeId(),
          candidate.credential(),
          () ->
              attempts.validateNotion(
                  job,
                  candidate,
                  notion,
                  scope.runScopeId(),
                  source.sourceObjectRef(),
                  source.version()));
    }
  }

  private void observe(
      ValidationProgress progress,
      long runScopeId,
      SecretFindingNormalizer.Credential credential,
      Supplier<CredentialValidationResult> operation) {
    try {
      progress.record(credential, runScopeId, operation.get());
    } catch (SecretJobFailure error) {
      throw error;
    } catch (RuntimeException ignored) {
      progress.failed++;
    }
  }

  private void check(
      ClaimedSecretJob job,
      long scopeId,
      SecretJobExecutionService execution,
      AtomicBoolean lost,
      long deadline) {
    check(job, scopeId, execution, lost, deadline, true);
  }

  private void check(
      ClaimedSecretJob job,
      long scopeId,
      SecretJobExecutionService execution,
      AtomicBoolean lost,
      long deadline,
      boolean respectWait) {
    if (lost.get() || !execution.renewLease(job.jobId(), job.leaseToken()))
      throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
    if (System.nanoTime() >= deadline)
      throw new SecretJobFailure(SecretJobFailureCode.SOURCE_UNAVAILABLE, true);
    boolean approved =
        Boolean.TRUE.equals(
            jdbc.queryForObject(
                """
                SELECT EXISTS(SELECT 1 FROM secret_scan_runs r JOIN secret_connections c USING(connection_id)
                JOIN secret_run_scopes rs USING(run_id) JOIN secret_connection_scopes s
                  ON s.scope_id=rs.scope_id AND s.connection_id=c.connection_id
                WHERE r.run_id=? AND r.job_id=? AND c.provider='NOTION' AND c.status='ACTIVE'
                  AND c.auth_ref=? AND c.scope_version=r.scope_version AND s.scope_id=? AND s.enabled
                  AND s.content_type='NOTION_PAGE_CONTENT' AND s.history_limit='CURRENT_VERSION_ONLY'
                  AND rs.scope_revision=s.revision)
                """,
                Boolean.class,
                job.runId(),
                job.jobId(),
                credentials.authRef(),
                scopeId));
    if (!approved) throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
    if (respectWait && currentWait() != null)
      throw new SecretJobFailure(SecretJobFailureCode.SOURCE_RATE_LIMITED, true);
  }

  private Instant currentWait() {
    OffsetDateTime until =
        jdbc.queryForObject(
            "SELECT max(source_retry_at) FROM secret_connections"
                + " WHERE provider='NOTION' AND auth_ref=? AND source_retry_at>clock_timestamp()",
            OffsetDateTime.class,
            credentials.authRef());
    return until == null ? null : until.toInstant();
  }

  private void waitUntil(
      ClaimedSecretJob job, Instant until, String code, SecretJobExecutionService execution) {
    String reason = "NOTION_RATE_LIMITED".equals(code) ? code : "NOTION_PROVIDER_UNAVAILABLE";
    persist(
        job,
        execution,
        () ->
            jdbc.update(
                "UPDATE secret_connections SET"
                    + " source_retry_at=GREATEST(source_retry_at,?),source_retry_reason=?"
                    + " WHERE provider='NOTION' AND auth_ref=?",
                until.atOffset(ZoneOffset.UTC),
                reason,
                credentials.authRef()));
  }

  private void recordExposureRange(long toolRunId, String range) {
    jdbc.update(
        "UPDATE secret_occurrences o SET exposure_range=? WHERE o.occurrence_id IN"
            + " (SELECT f.occurrence_id FROM secret_findings f WHERE f.tool_run_id=?"
            + " AND f.occurrence_id IS NOT NULL) AND o.exposure_range IS DISTINCT FROM ?",
        range,
        toolRunId,
        range);
  }

  private void finishScope(
      ClaimedSecretJob job,
      Scope scope,
      SecretJobExecutionService execution,
      String status,
      int count,
      int excluded,
      String code) {
    persist(
        job,
        execution,
        () ->
            jdbc.update(
                "UPDATE secret_run_scopes SET"
                    + " collection_status=?,object_count=?,excluded_object_count=?,failure_code=?,finished_at=clock_timestamp()"
                    + " WHERE run_scope_id=?",
                status,
                count,
                excluded,
                code,
                scope.runScopeId()));
  }

  private void persist(ClaimedSecretJob job, SecretJobExecutionService execution, Runnable action) {
    if (!execution.persistIfLeased(job.jobId(), job.leaseToken(), action))
      throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
  }

  private static SecretJobFailureCode failureCode(String code) {
    if (code != null && code.startsWith("DETECTOR_"))
      return SecretJobFailureCode.DETECTOR_TEMPORARY;
    if ("NOTION_RATE_LIMITED".equals(code)) return SecretJobFailureCode.SOURCE_RATE_LIMITED;
    return retryable(code)
        ? SecretJobFailureCode.SOURCE_UNAVAILABLE
        : SecretJobFailureCode.SOURCE_ACCESS_DENIED;
  }

  private static boolean retryable(String code) {
    return code == null
        || !Set.of(
                "INVALID_APPROVED_SCOPE",
                "NOTION_CONFIGURATION_ERROR",
                "NOTION_ACCESS_DENIED",
                "NOTION_NOT_FOUND",
                "NOTION_IN_TRASH",
                "NOTION_PROVIDER_ACCESS_BLOCKED")
            .contains(code);
  }

  private record Scope(long runScopeId, long scopeId, String reference, String history) {}

  private record ScopeResult(String collection, String detection, int objects, String failure) {}

  private static final class ValidationProgress {
    private final Set<String> seen = new HashSet<>();
    private int checked, inconclusive, failed;

    boolean first(SecretFindingNormalizer.Credential credential, long runScopeId) {
      return !seen.contains(key(credential, runScopeId));
    }

    private String key(SecretFindingNormalizer.Credential credential, long runScopeId) {
      byte[] digest =
          "CONFIRMED".equals(credential.componentState())
              ? credential.fingerprint()
              : credential.candidateLocator();
      return runScopeId + ":" + credential.issuer()
          + ":"
          + credential.credentialType()
          + ":"
          + credential.componentState()
          + ":"
          + credential.fingerprintKeyVersion()
          + ":"
          + HexFormat.of().formatHex(digest);
    }

    void record(SecretFindingNormalizer.Credential credential, long runScopeId, CredentialValidationResult result) {
      seen.add(key(credential, runScopeId));
      if (Set.of("VALID", "INVALID").contains(result.result())) checked++;
      else if (!Set.of("DISABLED", "SYNTHETIC_FIXTURE", "SOURCE_GUARD_BLOCKED", "VALIDATOR_NOT_ALLOWED")
          .contains(result.reasonCode())) inconclusive++;
    }

    String status() {
      return failed > 0 || inconclusive > 0 ? "PARTIAL" : checked > 0 ? "SUCCEEDED" : "SKIPPED";
    }
  }
}
