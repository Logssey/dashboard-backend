package com.logssey.secret.risk;

import com.logssey.secret.permission.core.SecretPermissionContext;
import com.logssey.secret.risk.core.SecretRiskAssessmentStore;
import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Reconstructs an observation-based work deadline, never evidence of simultaneous public exposure. */
final class SecretPrioritySignalBasis {
  private static final Set<String> IMPORTANT = Set.of("IDENTITY_ADMINISTRATION", "SECURITY_SETTINGS_WRITE",
      "RESOURCE_ADMINISTRATION", "PRODUCTION_DEPLOY", "SENSITIVE_DATA_READ");
  private static final List<String> COLLECTOR_BASELINE = List.of("collectorAuthRef", "collectorScopeVersion",
      "collectorScopeId", "collectorScopeRevision", "collectorApprovedRef");
  private final JdbcTemplate jdbc;
  private final SecretRiskAssessmentStore store;

  SecretPrioritySignalBasis(JdbcTemplate jdbc) { this.jdbc = jdbc; this.store = new SecretRiskAssessmentStore(jdbc); }

  /** The caller must supply only currently readable, approved, important permission candidates. */
  OffsetDateTime firstObserved(Map<String, Object> occurrence, OffsetDateTime now,
      List<Map<String, Object>> permittedCandidateObservations) {
    if (!"PRESENT".equals(occurrence.get("presence_status")))
      return null;
    var floor = cycleStart(occurrence);
    if (floor == null || floor.isAfter(now)) return null;
    var publicIntervals = publicIntervals(occurrence, floor, now);
    var credentialIntervals = new ArrayList<>(authenticationIntervals(occurrence, floor, now));
    if (!permittedCandidateObservations.isEmpty())
      credentialIntervals.addAll(permissionIntervals(occurrence, floor, now, permittedCandidateObservations));
    return currentIntersectionStart(publicIntervals, credentialIntervals, floor, now);
  }

  private OffsetDateTime cycleStart(Map<String, Object> o) {
    var floor = time(o.get("first_seen_at"));
    var cases = jdbc.queryForList("""
SELECT c.opened_at,(SELECT max(r.resumed_at) FROM secret_case_resume_events r
 WHERE r.case_id=c.case_id AND r.occurrence_id=co.occurrence_id) AS resumed_at
FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id)
WHERE co.occurrence_id=? AND c.is_current ORDER BY c.case_id DESC LIMIT 1
""", o.get("occurrence_id"));
    if (!cases.isEmpty()) {
      floor = later(floor, time(cases.getFirst().get("opened_at")));
      floor = later(floor, time(cases.getFirst().get("resumed_at")));
    }
    return floor;
  }

  private List<Interval> publicIntervals(Map<String, Object> o, OffsetDateTime floor, OffsetDateTime now) {
    var events = new ArrayList<Observation>();
    for (var row : jdbc.queryForList("""
SELECT e.*,e.safe_payload::text AS facts FROM secret_current_risk_evidence e
WHERE e.occurrence_id=? AND e.kind='ACCESS_SCOPE' AND e.source_kind='PROVIDER_OBSERVATION'
 AND e.writer_service_id='GITHUB_REPOSITORY_METADATA_V1' AND e.applicability_basis='OBSERVATION_ONLY'
 AND e.credential_revision=? AND e.scope_revision=? AND e.source_object_version IS NOT DISTINCT FROM ?
 AND e.collector_connection_id=? AND e.observed_at<=? ORDER BY e.observed_at,e.evidence_id
""", o.get("occurrence_id"), o.get("credential_revision"), o.get("scope_revision"),
        o.get("latest_object_version"), o.get("connection_id"), now)) {
      if (o.get("latest_object_version") == null) continue;
      var observed = time(row.get("observed_at"));
      var seen = time(row.get("source_presence_observed_at"));
      var recorded = time(row.get("recorded_at"));
      if (observed == null || seen == null || recorded == null) continue; // No inferred legacy timestamp.
      boolean positive = Boolean.TRUE.equals(store.map(row.get("facts").toString()).get("publicAccessConfirmed"));
      var until = earlier(time(row.get("expires_at")), observed.plusHours(6));
      events.add(new Observation(later(later(observed, seen), recorded), until, positive));
    }
    var result = new ArrayList<>(observationIntervals(events, floor, now));
    for (var row : jdbc.queryForList("""
SELECT e.*,e.safe_payload::text AS facts,(SELECT min(r.recorded_at) FROM secret_risk_evidence r
 WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='REVIEW' AND r.review_decision='ACCEPT'
 AND r.evidence_id>COALESCE((SELECT max(rejected.evidence_id) FROM secret_risk_evidence rejected
  WHERE rejected.related_evidence_id=e.evidence_id AND rejected.record_kind='REVIEW'
   AND rejected.review_decision='REJECT'),0)
 AND (e.verification_level='MANUAL_SUBMITTED' OR EXISTS(SELECT 1 FROM secret_risk_evidence rejected
  WHERE rejected.related_evidence_id=e.evidence_id AND rejected.record_kind='REVIEW'
   AND rejected.review_decision='REJECT'))) AS reviewed_at
FROM secret_current_risk_evidence e
WHERE e.occurrence_id=? AND e.kind='ACCESS_SCOPE' AND e.source_kind='MANUAL'
 AND e.applicability_basis='EFFECTIVE_INTERVAL' AND e.credential_revision=? AND e.scope_revision=?
 AND e.source_object_version IS NOT DISTINCT FROM ? AND e.observed_at<=?
""", o.get("occurrence_id"), o.get("credential_revision"), o.get("scope_revision"), o.get("latest_object_version"), now)) {
      if (!Boolean.TRUE.equals(store.map(row.get("facts").toString()).get("publicAccessConfirmed"))) continue;
      var observed = time(row.get("observed_at"));
      var from = time(row.get("fact_valid_from"));
      var until = time(row.get("fact_valid_until"));
      var seen = time(row.get("source_presence_observed_at"));
      var recorded = time(row.get("recorded_at"));
      if (observed == null || from == null || until == null || seen == null || recorded == null
          || seen.isBefore(from) || !seen.isBefore(until)) continue;
      var start = later(later(later(later(observed, seen), recorded), time(row.get("reviewed_at"))), floor);
      var end = earlier(earlier(until, time(row.get("expires_at"))), observed.plusHours(6));
      if (end != null && !start.isAfter(now) && end.isAfter(start)) result.add(new Interval(start, end));
    }
    return merge(result);
  }

  private List<Interval> authenticationIntervals(Map<String, Object> o, OffsetDateTime floor, OffsetDateTime now) {
    var events = new ArrayList<Observation>();
    var rows = jdbc.queryForList("""
SELECT a.result,a.provider_checked_at,a.completed_at,v.action_performed_at
FROM secret_current_validation_attempts a JOIN secret_validation_context v ON v.occurrence_id=a.occurrence_id
WHERE a.occurrence_id=? AND a.credential_set_id=? AND a.completed_at<=?
ORDER BY a.completed_at,a.attempt_id
""", o.get("occurrence_id"), o.get("credential_set_id"), now);
    for (var row : rows) {
      var completed = time(row.get("completed_at"));
      var observed = time(row.get("provider_checked_at"));
      var action = time(row.get("action_performed_at"));
      if (completed == null || (action != null && (observed == null || !observed.isAfter(action)))) continue;
      boolean positive = "VALID".equals(row.get("result")) && observed != null;
      events.add(new Observation(completed, positive ? observed.plusHours(6) : null, positive));
    }
    return observationIntervals(events, floor, now);
  }

  private List<Interval> permissionIntervals(Map<String, Object> o, OffsetDateTime floor, OffsetDateTime now,
      List<Map<String, Object>> permitted) {
    var context = new SecretPermissionContext(jdbc).read(((Number) o.get("occurrence_id")).longValue());
    var history = jdbc.queryForList("""
SELECT p.*,p.safe_facts::text AS facts,r.identity_id,r.collector_connection_id,r.baseline::text AS baseline,
 i.provider,i.principal_type,i.account_ref,i.principal_ref,i.principal_id,
 i.credential_revision AS identity_credential_revision,i.scope_revision AS identity_scope_revision,
 EXISTS(SELECT 1 FROM secret_permission_decisions d WHERE d.observation_id=p.observation_id
  AND d.decision='REJECTED') AS rejected
FROM secret_permission_observations p JOIN secret_permission_requests r USING(request_id)
JOIN secret_credential_identities i USING(identity_id)
WHERE r.occurrence_id=? AND p.observed_at<=? ORDER BY p.observed_at,p.observation_id
""", o.get("occurrence_id"), now);
    var byCollector = new LinkedHashMap<Long, List<Observation>>();
    for (var row : history) {
      var baseline = store.map(row.get("baseline").toString());
      boolean authorizedBaseline = permitted.stream().anyMatch(anchor ->
          Objects.equals(anchor.get("collector_connection_id"), row.get("collector_connection_id"))
              && sameCollectorBaseline(store.map(anchor.get("baseline").toString()), baseline));
      if (!authorizedBaseline || !sameIdentity(context, row)) continue;
      var historicalContext = new HashMap<>(context);
      historicalContext.put("identity_id", row.get("identity_id"));
      if (!Objects.equals(SecretPermissionContext.sourceVersion(historicalContext), baseline.get("sourceContextVersion")))
        continue;
      var observed = time(row.get("observed_at"));
      var recorded = time(row.get("created_at"));
      if (observed == null || recorded == null) continue;
      var facts = store.map(row.get("facts").toString());
      boolean positive = !Boolean.TRUE.equals(row.get("rejected")) && !"UNSUPPORTED".equals(row.get("status"))
          && facts.get("capabilities") instanceof Collection<?> capabilities
          && capabilities.stream().anyMatch(IMPORTANT::contains);
      var until = earlier(time(row.get("expires_at")), observed.plusHours(24));
      byCollector.computeIfAbsent(((Number) row.get("collector_connection_id")).longValue(), ignored -> new ArrayList<>())
          .add(new Observation(later(observed, recorded), until, positive));
    }
    var result = new ArrayList<Interval>();
    byCollector.values().forEach(events -> result.addAll(observationIntervals(events, floor, now)));
    return merge(result);
  }

  private static boolean sameIdentity(Map<String, Object> current, Map<String, Object> row) {
    return Objects.equals(current.get("credential_revision"), row.get("identity_credential_revision"))
        && Objects.equals(current.get("scope_revision"), row.get("identity_scope_revision"))
        && Objects.equals(current.get("issuer"), row.get("provider"))
        && Objects.equals(current.get("principal_type"), row.get("principal_type"))
        && Objects.equals(current.get("account_ref"), row.get("account_ref"))
        && Objects.equals(current.get("principal_ref"), row.get("principal_ref"))
        && Objects.equals(current.get("principal_id"), row.get("principal_id"));
  }

  private static boolean sameCollectorBaseline(Map<String, Object> left, Map<String, Object> right) {
    return COLLECTOR_BASELINE.stream().allMatch(key -> left.get(key) != null
        && Objects.toString(left.get(key)).equals(Objects.toString(right.get(key), "")));
  }

  record Observation(OffsetDateTime at, OffsetDateTime until, boolean positive) { }
  record Interval(OffsetDateTime from, OffsetDateTime until) { }

  /** A contrary observation cuts a positive interval; a gap is never bridged by a later refresh. */
  static List<Interval> observationIntervals(List<Observation> observations, OffsetDateTime floor, OffsetDateTime now) {
    var result = new ArrayList<Interval>();
    var available = observations.stream().filter(o -> o.at() != null && !o.at().isAfter(now)).toList();
    for (var observation : available) {
      if (!observation.positive() || observation.until() == null) continue;
      var end = observation.until();
      for (var contrary : available)
        if (!contrary.positive() && !contrary.at().isBefore(observation.at()) && contrary.at().isBefore(end))
          end = contrary.at();
      var start = later(observation.at(), floor);
      if (end.isAfter(start)) result.add(new Interval(start, end));
    }
    return merge(result);
  }

  static OffsetDateTime currentIntersectionStart(List<Interval> publicIntervals, List<Interval> credentials,
      OffsetDateTime floor, OffsetDateTime now) {
    var intersections = new ArrayList<Interval>();
    for (var publicSignal : merge(publicIntervals)) for (var credential : merge(credentials)) {
      var start = later(later(publicSignal.from(), credential.from()), floor);
      var end = earlier(publicSignal.until(), credential.until());
      if (start != null && end != null && end.isAfter(start)) intersections.add(new Interval(start, end));
    }
    return merge(intersections).stream().filter(i -> !i.from().isAfter(now) && i.until().isAfter(now))
        .map(Interval::from).findFirst().orElse(null);
  }

  private static List<Interval> merge(List<Interval> intervals) {
    var sorted = intervals.stream().filter(i -> i.from() != null && i.until() != null && i.until().isAfter(i.from()))
        .sorted(Comparator.comparing(Interval::from)).toList();
    var result = new ArrayList<Interval>();
    for (var item : sorted) {
      if (result.isEmpty() || item.from().isAfter(result.getLast().until())) result.add(item);
      else {
        var last = result.removeLast();
        result.add(new Interval(last.from(), later(last.until(), item.until())));
      }
    }
    return result;
  }

  private static OffsetDateTime time(Object value) { return SecretRiskAssessmentStore.time(value); }
  private static OffsetDateTime later(OffsetDateTime a, OffsetDateTime b) { return a == null ? b : b == null || a.isAfter(b) ? a : b; }
  private static OffsetDateTime earlier(OffsetDateTime a, OffsetDateTime b) { return a == null || b == null ? null : a.isBefore(b) ? a : b; }
}
