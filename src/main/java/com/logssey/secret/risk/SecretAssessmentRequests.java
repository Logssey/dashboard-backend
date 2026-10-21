package com.logssey.secret.risk;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretAssessmentRequests {
  public record Request(Long expectedEvidenceRevision, String idempotencyKey) {}

  final JdbcTemplate jdbc;
  final SecretAccessService access;
  final SecretRiskCommands commands;
  final SecretRiskEvidenceService evidence;

  public SecretAssessmentRequests(
      JdbcTemplate jdbc,
      SecretAccessService access,
      SecretRiskCommands commands,
      SecretRiskEvidenceService evidence) {
    this.jdbc = jdbc;
    this.access = access;
    this.commands = commands;
    this.evidence = evidence;
  }

  public Map<String, Object> request(String login, long occurrence, Request r) {
    if (r == null || r.expectedEvidenceRevision() == null) throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    evidence.authorize(actor, occurrence);
    return commands.execute(
        actor,
        "SEVERITY_ASSESSMENT_REQUESTED",
        r.idempotencyKey(),
        List.of(occurrence, r.expectedEvidenceRevision()),
        () -> evidence.authorize(actor, occurrence),
        () -> {
          var o = evidence.lock(occurrence, r.expectedEvidenceRevision());
          if ("METADATA_ONLY"
              .equals(
                  jdbc.queryForObject(
                      "SELECT component_state FROM secret_credential_sets WHERE"
                          + " credential_set_id=?",
                      String.class,
                      o.get("credential_set_id")))) throw new ApiException(ErrorCode.UNPROCESSABLE);
          long job =
              jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, occurrence);
          var result = new LinkedHashMap<String, Object>();
          result.put("occurrenceId", occurrence);
          result.put("evidenceRevision", r.expectedEvidenceRevision());
          result.put("requestId", job);
          result.put("jobId", job);
          result.put("runId", null);
          result.put("status", "PENDING");
          result.put(
              "reused",
              jdbc.queryForObject(
                  "SELECT attempt_no>0 FROM secret_jobs WHERE job_id=?", Boolean.class, job));
          return result;
        });
  }

  public Map<String, Object> status(String login, long id) {
    var rows =
        jdbc.queryForList(
            "SELECT job_id,target_occurrence_id,status,last_error_code FROM secret_jobs WHERE"
                + " job_id=? AND kind='ASSESS' AND purpose='SEVERITY_ASSESSMENT'",
            id);
    if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
    var r = rows.getFirst();
    access.requireOccurrenceRead(
        access.requirePrincipal(login), ((Number) r.get("target_occurrence_id")).longValue());
    var result = new LinkedHashMap<String, Object>();
    result.put("requestId", id);
    result.put("jobId", id);
    result.put("runId", null);
    result.put("status", r.get("status"));
    result.put("reasonCode", r.get("last_error_code"));
    result.put(
        "assessmentId",
        jdbc.queryForObject(
            "SELECT max(assessment_id) FROM secret_severity_assessments WHERE request_job_id=? AND"
                + " record_kind='AUTO_RESULT'",
            Long.class,
            id));
    return result;
  }
}
