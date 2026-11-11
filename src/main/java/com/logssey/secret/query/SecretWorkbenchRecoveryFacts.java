package com.logssey.secret.query;

import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

import com.logssey.secret.access.*;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.snapshot.SecretReadSnapshots.*;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.IntFunction;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** Recovery summaries use the same ACL-filtered frozen subjects as their work lists. */
final class SecretWorkbenchRecoveryFacts {
  private final JdbcTemplate jdbc;
  private final SecretAccessService access;
  private final SecretCoverageService coverage;
  private final SecretReadSnapshots snapshots;

  SecretWorkbenchRecoveryFacts(
      JdbcTemplate jdbc,
      SecretAccessService access,
      SecretCoverageService coverage,
      SecretReadSnapshots snapshots) {
    this.jdbc = jdbc;
    this.access = access;
    this.coverage = coverage;
    this.snapshots = snapshots;
  }

  void addScopes(
      String login,
      SecretPrincipal actor,
      SecretWorkbenchService.Filters filters,
      List<Subject> subjects) {
    var selectedIds = new ArrayList<Long>();
    var providerScopeIds = new TreeMap<String, List<Long>>();
    long configuredConnections = 0;
    for (var connection :
        jdbc.queryForList(
            "SELECT connection_id,provider FROM secret_connections ORDER BY connection_id")) {
      long id = ((Number) connection.get("connection_id")).longValue();
      if (!access.canReadConnectionFacts(actor, id)
          || filters.connectionId() != null && filters.connectionId() != id
          || !filters.source().equals("ALL")
              && !filters.source().equals(connection.get("provider"))) continue;
      configuredConnections++;
      subjects.add(new Subject("HealthConnection", id, null,
          facts("connectionId", id, "source", connection.get("provider"))));
      for (var item : pages(page -> coverage.scopes(login, id, "ALL", "ALL", false, page, 100))) {
        long scope = ((Number) item.get("scopeId")).longValue();
        boolean selected = filters.origin().equals("ALL") || filters.origin().equals(item.get("origin"));
        boolean paused = !"ACTIVE".equals(item.get("connectionStatus"));
        if (selected) {
          subjects.add(new Subject("HealthScope", scope, null, item));
          selectedIds.add(scope);
          providerScopeIds.computeIfAbsent((String) connection.get("provider"), key -> new ArrayList<>()).add(scope);
        }
        if (!(item.get("setupReasonCodes") instanceof List<?> reasons) || reasons.isEmpty())
          continue;
        if (paused) subjects.add(new Subject("PausedSetupScope", scope, null, item));
        else if (selected) subjects.add(new Subject("UnclassifiedScope", scope, null, item));
        else if ("UNCLASSIFIED".equals(item.get("origin")))
          subjects.add(new Subject("UnassignedSetupScope", scope, null, item));
      }
    }
    // This marker distinguishes a new snapshot with zero connections from an older snapshot
    // that never captured connection facts. Never infer zero from an empty selected origin.
    subjects.add(new Subject("CollectionConfiguration", 0, null,
        facts("configuredConnectionCount", configuredConnections)));
    // A per-scope success is not a success for the whole selected set.
    addCompleteRun(subjects, "CollectionCompleteRun", null, selectedIds);
    providerScopeIds.forEach((source, ids) -> addCompleteRun(subjects, "ProviderCompleteRun", source, ids));
  }

  private void addCompleteRun(List<Subject> subjects, String type, String source, List<Long> selectedIds) {
    if (!selectedIds.isEmpty()) {
      var runs =
          new NamedParameterJdbcTemplate(jdbc)
              .queryForList(
                  """
SELECT r.run_id,r.connection_id,r.requested_at,r.finished_at FROM secret_scan_runs r
JOIN secret_jobs j USING(job_id) WHERE j.kind='FULL_SCAN' AND j.status='SUCCEEDED'
  AND r.result_status='SUCCEEDED' AND r.collection_status='SUCCEEDED' AND r.finished_at IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.scope_id IN(:ids)
    AND NOT EXISTS(SELECT 1 FROM secret_scope_outcomes rs WHERE rs.run_id=r.run_id
      AND rs.scope_id=s.scope_id AND rs.scope_revision=s.revision AND r.connection_id=s.connection_id
      AND rs.scope_outcome='SUCCEEDED' AND rs.job_status='SUCCEEDED'))
ORDER BY r.finished_at DESC NULLS LAST,r.run_id DESC LIMIT 1
""",
                  Map.of("ids", selectedIds));
      if (!runs.isEmpty()) {
        var run = runs.getFirst();
        subjects.add(
            new Subject(
                type,
                ((Number) run.get("run_id")).longValue(),
                null,
                facts(
                    "runId",
                    run.get("run_id"),
                    "connectionId",
                    run.get("connection_id"),
                    "source",
                    source,
                    "status",
                    "SUCCEEDED",
                    "requestedAt",
                    time(run.get("requested_at")),
                    "finishedAt",
                    time(run.get("finished_at")))));
      }
    }
  }

  Map<String, Object> previews(Header header, boolean responseAllowed, boolean securityAllowed) {
    return facts(
        "response",
        preview(
            header, "ResponseCase", "ResponseCase", responseAllowed, Set.of("OPEN", "IN_PROGRESS")),
        "revalidation",
        preview(
            header,
            "ResponseCase",
            "ResponseCase",
            responseAllowed,
            Set.of("REVALIDATION_PENDING")),
        "decision",
        preview(header, "DecisionOccurrence", "Occurrence", securityAllowed, Set.of()),
        "review", reviewPreview(header, securityAllowed));
  }

  /** Both the card and the paginated destination use this union of the same frozen subjects. */
  List<Map<String, Object>> reviewRows(Header header) {
    var byOccurrence = new LinkedHashMap<Long, Map<String, Object>>();
    for (String type : List.of("LinkOccurrence", "DecisionOccurrence")) {
      for (var original : snapshots.page(header, type, 0, Integer.MAX_VALUE)) {
        long occurrenceId = ((Number) original.get("occurrenceId")).longValue();
        if (byOccurrence.containsKey(occurrenceId)) continue;
        var row = new LinkedHashMap<>(original);
        row.put("nextActionCode", type.equals("LinkOccurrence") ? "LINK_CASE" : "REVIEW_EVIDENCE");
        row.put("taskGuidance", SecretTaskGuidance.location(row));
        byOccurrence.put(occurrenceId, row);
      }
    }
    return List.copyOf(byOccurrence.values());
  }

  private Map<String, Object> reviewPreview(Header header, boolean allowed) {
    var rows = allowed ? reviewRows(header) : List.<Map<String, Object>>of();
    return facts("status", allowed ? "AVAILABLE" : "NOT_AUTHORIZED", "items", rows.stream().limit(5).toList(),
        "total", allowed ? rows.size() : null, "unit", "Occurrence", "snapshotId", header.snapshotId());
  }

  private Map<String, Object> preview(
      Header header, String type, String unit, boolean allowed, Set<String> stages) {
    var items =
        allowed
            ? snapshots.page(header, type, 0, Integer.MAX_VALUE).stream()
                .filter(item -> stages.isEmpty() || stages.contains(item.get("stage")))
                .toList()
            : List.<Map<String, Object>>of();
    return facts(
        "status",
        allowed ? "AVAILABLE" : "NOT_AUTHORIZED",
        "items",
        items.stream().limit(5).toList(),
        "total",
        allowed ? items.size() : null,
        "unit",
        unit,
        "snapshotId",
        header.snapshotId());
  }

  Map<String, Object> setup(Header header, String origin, boolean allowed) {
    var selected =
        allowed
            ? snapshots.page(header, "UnclassifiedScope", 0, Integer.MAX_VALUE)
            : List.<Map<String, Object>>of();
    var unclassified =
        allowed
            ? snapshots.page(header, "UnassignedSetupScope", 0, Integer.MAX_VALUE)
            : List.<Map<String, Object>>of();
    var paused =
        allowed
            ? snapshots.page(header, "PausedSetupScope", 0, Integer.MAX_VALUE)
            : List.<Map<String, Object>>of();
    var all = new ArrayList<Map<String, Object>>();
    all.addAll(selected);
    all.addAll(unclassified);
    all.addAll(paused);
    return facts(
        "status",
        allowed ? "AVAILABLE" : "NOT_AUTHORIZED",
        "selectedOrigin",
        origin,
        "selectedOriginScopeCount",
        allowed ? selected.size() : null,
        "unclassifiedScopeCount",
        allowed ? unclassified.size() : null,
        "pausedScopeCount",
        allowed ? paused.size() : null,
        "actionableScopeCount",
        allowed
            ? all.stream()
                .filter(
                    item ->
                        item.get("taskGuidance") instanceof Map<?, ?> task
                            && Boolean.TRUE.equals(task.get("canExecute")))
                .count()
            : null,
        "reasonCounts",
        reasonCounts(all),
        "selectedReasonCounts",
        reasonCounts(selected),
        "unclassifiedReasonCounts",
        reasonCounts(unclassified),
        "pausedReasonCounts",
        reasonCounts(paused),
        "items",
        selected.stream().limit(10).toList(),
        "unclassifiedItems",
        unclassified.stream().limit(10).toList(),
        "pausedItems",
        paused.stream().limit(10).toList(),
        "globalGroupsIgnoreOrigin",
        true,
        "notApplicableFilters",
        List.of("provider", "environment", "assignee"),
        "snapshotId",
        header.snapshotId());
  }

  Map<String, Object> health(Header header, String origin, boolean allowed) {
    var items =
        allowed
            ? snapshots.page(header, "HealthScope", 0, Integer.MAX_VALUE)
            : List.<Map<String, Object>>of();
    var connections = allowed ? snapshots.page(header, "HealthConnection", 0, Integer.MAX_VALUE)
        : List.<Map<String, Object>>of();
    var configuration = allowed ? snapshots.page(header, "CollectionConfiguration", 0, 1)
        : List.<Map<String, Object>>of();
    boolean configurationKnown = !configuration.isEmpty();
    var providerComplete = allowed ? snapshots.page(header, "ProviderCompleteRun", 0, Integer.MAX_VALUE)
        : List.<Map<String, Object>>of();
    var sources = new TreeSet<String>();
    items.forEach(item -> sources.add((String) item.get("source")));
    connections.forEach(item -> sources.add((String) item.get("source")));
    var providers = new ArrayList<Map<String, Object>>();
    for (String source : sources) {
      var selected = items.stream().filter(item -> source.equals(item.get("source"))).toList();
      var row = healthFacts(selected, providerComplete.stream().filter(item -> source.equals(item.get("source")))
          .findFirst().orElse(null), 5);
      row.put("source", source);
      row.put("configuredConnectionCount", configurationKnown
          ? connections.stream().filter(item -> source.equals(item.get("source"))).count() : null);
      providers.add(row);
    }
    var complete = allowed ? snapshots.page(header, "CollectionCompleteRun", 0, 1)
        : List.<Map<String, Object>>of();
    var result = healthFacts(items, complete.isEmpty() ? null : complete.getFirst(), 10);
    result.putAll(facts("status", allowed ? "AVAILABLE" : "NOT_AUTHORIZED", "origin", origin,
        "configuredConnectionCount", configurationKnown ? configuration.getFirst().get("configuredConnectionCount") : null,
        "configuredConnectionsIgnoreOrigin", true, "providers", providers,
        "basis", "CURRENT_SCOPE_REVISION", "notApplicableFilters", List.of("provider", "environment", "assignee"),
        "snapshotId", header.snapshotId()));
    if (!allowed) {
      result.put("approvedScopeCount", null);
      result.put("gapScopeCount", null);
      result.put("counts", null);
    }
    return result;
  }

  private Map<String, Object> healthFacts(List<Map<String, Object>> items, Map<String, Object> complete, int limit) {
    var counts = new LinkedHashMap<String, Long>();
    for (String key :
        List.of("success", "partial", "failed", "notRun", "paused", "running", "incomplete"))
      counts.put(key, 0L);
    Map<String, Object> latest = null, success = null;
    long gapScopes = 0;
    for (var item : items) {
      var observation = block(item.get("coverage"));
      var attempt = contextualAttempt(item, observation.get("lastAttempt"));
      var successful = contextualAttempt(item, observation.get("lastSuccessfulScan"));
      if (!attempt.isEmpty() && newer(attempt, latest)) latest = attempt;
      if (!successful.isEmpty() && newer(successful, success)) success = successful;
      if (observation.get("gapReasonCodes") instanceof List<?> gaps && !gaps.isEmpty()) gapScopes++;
      String bucket =
          Boolean.TRUE.equals(observation.get("isPaused"))
              ? "paused"
              : Boolean.TRUE.equals(observation.get("isRunning"))
                  ? "running"
                  : attempt.isEmpty()
                      ? "notRun"
                      : "SUCCEEDED".equals(attempt.get("scopeOutcome"))
                          ? "success"
                          : "PARTIAL".equals(attempt.get("scopeOutcome"))
                              ? "partial"
                              : "FAILED".equals(attempt.get("scopeOutcome"))
                                  ? "failed"
                                  : "SKIPPED".equals(attempt.get("scopeOutcome"))
                                      ? "notRun"
                                      : "incomplete";
      counts.merge(bucket, 1L, Long::sum);
    }
    return facts(
        "approvedScopeCount",
        items.size(),
        "gapScopeCount", gapScopes,
        "counts",
        counts,
        "lastAttempt",
        latest,
        "lastScopeSuccess",
        success,
        "lastCompleteSuccess",
        complete,
        "items",
        items.stream()
            .sorted(
                Comparator.comparingInt(this::healthPriority)
                    .thenComparingLong(item -> ((Number) item.get("scopeId")).longValue()))
            .limit(limit)
            .toList());
  }

  private Map<String, Object> contextualAttempt(Map<String, Object> scope, Object value) {
    var observation = block(value);
    if (observation.isEmpty()) return observation;
    var result = new LinkedHashMap<>(observation);
    result.put("connectionId", scope.get("connectionId"));
    result.put("scopeId", scope.get("scopeId"));
    result.put("source", scope.get("source"));
    return result;
  }

  private int healthPriority(Map<String, Object> item) {
    var observation = block(item.get("coverage"));
    var attempt = block(observation.get("lastAttempt"));
    if (Boolean.TRUE.equals(observation.get("isPaused"))) return 3;
    if (Set.of("FAILED", "PARTIAL").contains(attempt.getOrDefault("scopeOutcome", ""))) return 0;
    if (Boolean.TRUE.equals(observation.get("isRunning"))) return 1;
    if (observation.get("gapReasonCodes") instanceof List<?> gaps && !gaps.isEmpty()) return 2;
    return 4;
  }

  private Map<String, Long> reasonCounts(List<Map<String, Object>> items) {
    var counts = new TreeMap<String, Long>();
    for (var item : items) {
      if (item.get("setupReasonCodes") instanceof List<?> reasons)
        for (var code : new HashSet<>(reasons)) counts.merge(code.toString(), 1L, Long::sum);
      if (!"ACTIVE".equals(item.get("connectionStatus")))
        counts.merge("CONNECTION_PAUSED", 1L, Long::sum);
    }
    return counts;
  }

  private boolean newer(Map<String, Object> left, Map<String, Object> right) {
    if (right == null) return true;
    var a = time(left.get("requestedAt"));
    var b = time(right.get("requestedAt"));
    return a != null && (b == null || a.isAfter(b));
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> block(Object value) {
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  private OffsetDateTime time(Object value) {
    return value instanceof OffsetDateTime at
        ? at
        : value instanceof java.sql.Timestamp at
            ? at.toInstant().atOffset(java.time.ZoneOffset.UTC)
            : value instanceof String text ? OffsetDateTime.parse(text) : null;
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> pages(IntFunction<Map<String, Object>> query) {
    var items = new ArrayList<Map<String, Object>>();
    for (int page = 0; ; page++) {
      var result = query.apply(page);
      var current = (List<Map<String, Object>>) result.get("items");
      items.addAll(current);
      if (current.isEmpty() || items.size() >= ((Number) result.get("total")).longValue())
        return items;
    }
  }
}
