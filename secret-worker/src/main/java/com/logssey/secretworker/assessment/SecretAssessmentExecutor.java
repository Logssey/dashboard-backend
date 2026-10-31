package com.logssey.secretworker.assessment;

import com.logssey.secret.risk.core.SecretRiskAssessmentStore;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;

/** ASSESS has no ScanRun and is never claimed by the external collector executor. */
@Service
public class SecretAssessmentExecutor {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final SecretRiskAssessmentStore store;

  public record Lease(
      long jobId,
      long occurrenceId,
      long expectedRevision,
      long policyId,
      UUID token,
      long generation) {}

  public SecretAssessmentExecutor(JdbcTemplate jdbc, PlatformTransactionManager manager) {
    this.jdbc = jdbc;
    this.tx = new TransactionTemplate(manager);
    this.store = new SecretRiskAssessmentStore(jdbc);
  }

  public Optional<Lease> claim() {
    return tx.execute(
        status -> {
          jdbc.update(
              "UPDATE secret_jobs SET status=CASE WHEN attempt_no>=max_attempts THEN 'FAILED' ELSE"
                  + " 'PENDING'"
                  + " END,available_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='ASSESSMENT_LEASE_EXPIRED'"
                  + " WHERE kind='ASSESS' AND status='LEASED' AND lease_until<=clock_timestamp()");
          var jobs =
              jdbc.queryForList(
                  "SELECT"
                      + " job_id,target_occurrence_id,expected_evidence_revision,(expected_context->>'policyId')::bigint"
                      + " AS policy_id,lease_generation FROM secret_jobs WHERE kind='ASSESS' AND"
                      + " purpose='SEVERITY_ASSESSMENT' AND status='PENDING' AND"
                      + " available_at<=clock_timestamp() AND attempt_no<max_attempts ORDER BY"
                      + " available_at,job_id LIMIT 1 FOR UPDATE SKIP LOCKED");
          if (jobs.isEmpty()) return Optional.empty();
          var j = jobs.getFirst();
          UUID token = UUID.randomUUID();
          long generation = num(j, "lease_generation") + 1;
          jdbc.update(
              "UPDATE secret_jobs SET"
                  + " status='LEASED',lease_owner=?,lease_token=?,lease_generation=?,lease_until=clock_timestamp()+interval"
                  + " '30 seconds',attempt_no=attempt_no+1 WHERE job_id=?",
              token.toString(),
              token,
              generation,
              num(j, "job_id"));
          return Optional.of(
              new Lease(
                  num(j, "job_id"),
                  num(j, "target_occurrence_id"),
                  num(j, "expected_evidence_revision"),
                  num(j, "policy_id"),
                  token,
                  generation));
        });
  }

  public boolean execute(Lease lease) {
    try {
      return Boolean.TRUE.equals(
          tx.execute(
              status -> {
                var rows =
                    jdbc.queryForList(
                        "SELECT status,lease_token,lease_generation,lease_until FROM secret_jobs"
                            + " WHERE job_id=? AND kind='ASSESS' FOR UPDATE",
                        lease.jobId());
                if (rows.isEmpty() || !owned(rows.getFirst(), lease)) return false;
                var o = store.location(lease.occurrenceId(), true);
                long active = num(store.activePolicy(), "policy_id");
                if (num(o, "risk_evidence_revision") != lease.expectedRevision()
                    || active != lease.policyId()) {
                  jdbc.update(
                      "UPDATE secret_jobs SET"
                          + " status='CANCELLED',finished_at=clock_timestamp(),last_error_code='STALE_BASELINE',lease_until=NULL,lease_owner=NULL,lease_token=NULL"
                          + " WHERE job_id=?",
                      lease.jobId());
                  jdbc.queryForObject(
                      "SELECT secret_queue_assessment(?)", Long.class, lease.occurrenceId());
                  return true;
                }
                long assessment =
                    store.assess(lease.occurrenceId(), lease.expectedRevision(), lease.jobId());
                if (!Boolean.TRUE.equals(
                    jdbc.queryForObject(
                        "SELECT lease_until>clock_timestamp() AND lease_token=? AND"
                            + " lease_generation=? FROM secret_jobs WHERE job_id=?",
                        Boolean.class,
                        lease.token(),
                        lease.generation(),
                        lease.jobId()))) throw new IllegalStateException("ASSESSMENT_LEASE_LOST");
                jdbc.update(
                    "UPDATE secret_jobs SET"
                        + " status='SUCCEEDED',finished_at=clock_timestamp(),lease_until=NULL,lease_owner=NULL,lease_token=NULL,last_error_code=NULL"
                        + " WHERE job_id=?",
                    lease.jobId());
                return assessment >= 0;
              }));
    } catch (RuntimeException failure) {
      tx.executeWithoutResult(
          status ->
              jdbc.update(
                  "UPDATE secret_jobs SET status=CASE WHEN attempt_no>=max_attempts THEN 'FAILED'"
                      + " ELSE 'PENDING' END,available_at=clock_timestamp()+interval '30"
                      + " seconds',last_error_code='ASSESSMENT_PROCESSING_FAILED',lease_owner=NULL,lease_token=NULL,lease_until=NULL"
                      + " WHERE job_id=? AND lease_token=? AND lease_generation=? AND"
                      + " status='LEASED'",
                  lease.jobId(),
                  lease.token(),
                  lease.generation()));
      return false;
    }
  }

  public void queueExpired() {
    tx.executeWithoutResult(
        status -> {
          var events =
              jdbc.queryForList(
                  """
SELECT o.occurrence_id,a.assessment_id FROM secret_occurrences o
JOIN LATERAL(SELECT assessment_id,input_snapshot,matched_rule_id FROM secret_severity_assessments a WHERE a.occurrence_id=o.occurrence_id AND a.record_kind='AUTO_RESULT' ORDER BY occurrence_sequence DESC LIMIT 1)a ON true
WHERE ((a.input_snapshot->>'evidenceValidUntil')::timestamptz<=clock_timestamp() OR a.matched_rule_id='R00' AND NOT EXISTS(SELECT 1 FROM secret_occurrence_policy_results storage WHERE storage.occurrence_id=o.occurrence_id AND storage.policy_result='ALLOWED' AND NOT storage.requires_reassessment))
AND NOT EXISTS(SELECT 1 FROM secret_jobs j WHERE j.kind='ASSESS' AND j.target_occurrence_id=o.occurrence_id AND
 (j.status IN('PENDING','LEASED') OR j.expected_context->>'expiryBaselineAssessmentId'=a.assessment_id::text))
ORDER BY o.occurrence_id LIMIT 100 FOR UPDATE OF o SKIP LOCKED
""");
          for (var event : events) {
            long id = num(event, "occurrence_id");
            jdbc.update(
                "UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1"
                    + " WHERE occurrence_id=?",
                id);
            Long job = jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, id);
            if (job != null)
              jdbc.update(
                  "UPDATE secret_jobs SET"
                      + " expected_context=expected_context||jsonb_build_object('expiryBaselineAssessmentId',?::bigint)"
                      + " WHERE job_id=?",
                  num(event, "assessment_id"),
                  job);
          }
          var overrides =
              jdbc.queryForList(
                  """
SELECT o.occurrence_id,p.assessment_id FROM secret_occurrences o
JOIN secret_current_occurrence_risks current_risk USING(occurrence_id)
JOIN LATERAL(SELECT * FROM secret_severity_assessments head WHERE head.occurrence_id=o.occurrence_id AND head.record_kind='APPLICATION' ORDER BY head.occurrence_sequence DESC LIMIT 1)head ON true
   JOIN secret_severity_assessments p ON p.assessment_id=CASE WHEN head.decision='HOLD' THEN head.previous_effective_assessment_id WHEN head.decision='EXPIRE_OVERRIDE' THEN head.restored_effective_assessment_id ELSE head.target_assessment_id END
WHERE p.record_kind='OVERRIDE_PROPOSAL' AND current_risk.override_expired
AND NOT EXISTS(SELECT 1 FROM secret_severity_assessments x WHERE x.target_assessment_id=p.assessment_id AND x.record_kind='APPLICATION' AND x.decision='EXPIRE_OVERRIDE')
AND NOT EXISTS(SELECT 1 FROM secret_jobs j WHERE j.kind='ASSESS' AND j.target_occurrence_id=o.occurrence_id AND
 (j.status IN('PENDING','LEASED') OR j.expected_context->>'expiryOverrideId'=p.assessment_id::text)) LIMIT 100 FOR UPDATE OF o SKIP LOCKED
""");
          for (var event : overrides) {
            long id = num(event, "occurrence_id");
            jdbc.update(
                "UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1"
                    + " WHERE occurrence_id=?",
                id);
            Long job = jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, id);
            if (job != null)
              jdbc.update(
                  "UPDATE secret_jobs SET"
                      + " expected_context=expected_context||jsonb_build_object('expiryOverrideId',?::bigint)"
                      + " WHERE job_id=?",
                  num(event, "assessment_id"),
                  job);
          }
        });
  }

  private boolean owned(Map<String, Object> row, Lease lease) {
    return "LEASED".equals(row.get("status"))
        && lease.token().equals(row.get("lease_token"))
        && lease.generation() == num(row, "lease_generation")
        && SecretRiskAssessmentStore.time(row.get("lease_until"))
            .isAfter(OffsetDateTime.now(ZoneOffset.UTC));
  }

  private static long num(Map<String, Object> row, String key) {
    return ((Number) row.get(key)).longValue();
  }
}
