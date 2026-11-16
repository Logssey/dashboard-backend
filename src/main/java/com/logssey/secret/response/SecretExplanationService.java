package com.logssey.secret.response;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.run.SecretRunQueryService;
import com.logssey.secret.run.SecretRunService;
import com.logssey.secret.run.SecretRunStatusResponse;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretExplanationService {
    private final SecretRunService runs;
    private final SecretRunQueryService runQueries;
    private final SecretCaseService cases;
    private final SecretCaseRepository caseRepository;
    private final SecretGuideRepository guideRepository;
    private final JdbcTemplate jdbc;
    private final ObjectProvider<ClaudeSecretGuideProvider> providers;

    public SecretExplanationService(SecretRunService runs, SecretRunQueryService runQueries,
            SecretCaseService cases, SecretCaseRepository caseRepository, SecretGuideRepository guideRepository,
            JdbcTemplate jdbc, ObjectProvider<ClaudeSecretGuideProvider> providers) {
        this.runs = runs;
        this.runQueries = runQueries;
        this.cases = cases;
        this.caseRepository = caseRepository;
        this.guideRepository = guideRepository;
        this.jdbc = jdbc;
        this.providers = providers;
    }

    public SecretExplanationResponse run(long runId, String login, boolean requested) {
        return explain(() -> runSnapshot(runId, login), requested);
    }

    public SecretExplanationResponse responseCase(long caseId, String login, boolean requested) {
        return explain(() -> caseSnapshot(caseId, login), requested);
    }

    private SecretExplanationResponse explain(Supplier<Snapshot> read, boolean requested) {
        var snapshot = read.get();
        var provider = providers.getIfAvailable();
        String reason = snapshot.aiReadable() && provider != null ? provider.configurationReason()
                : snapshot.aiReadable() ? "DISABLED" : "ALL_LOCATIONS_ACCESS_REQUIRED";
        boolean available = "READY".equals(reason);
        if (!requested || !available) {
            return response(snapshot, null, List.of(), new SecretGuideReadiness(
                    available ? "READY" : "UNAVAILABLE", reason, available, requested, false, false)
                    .withProvider("CLAUDE", provider == null ? null : provider.modelId(), null));
        }
        var selection = provider.explain(snapshot.context());
        var current = read.get();
        if (!current.aiReadable() || !current.context().equals(snapshot.context())
                || !current.fingerprint().equals(snapshot.fingerprint())) {
            return response(current, null, List.of(), new SecretGuideReadiness("FALLBACK", "CONTEXT_CHANGED",
                    current.aiReadable(), true, selection.providerCalled(), selection.cached())
                    .withProvider("CLAUDE", provider.modelId(), null));
        }
        return response(current, selection.summary(), selection.actionCodes(),
                new SecretGuideReadiness(selection.summary() == null ? "FALLBACK" : "GENERATED",
                        selection.reasonCode(), true, true, selection.providerCalled(), selection.cached())
                        .withProvider("CLAUDE", provider.modelId(), selection.generatedAt()));
    }

    private SecretExplanationResponse response(Snapshot snapshot, String summary, List<String> selected,
                                                SecretGuideReadiness readiness) {
        var context = snapshot.context();
        var actions = new ArrayList<SecretExplanationResponse.Action>();
        for (String code : selected.isEmpty() ? context.actions() : selected) {
            if (!context.actions().contains(code)) continue;
            actions.add(new SecretExplanationResponse.Action(code, SecretExplanationCatalog.actionLabel(code),
                    snapshot.links().get(code)));
        }
        return new SecretExplanationResponse(SecretExplanationCatalog.VERSION, context.topic(),
                summary == null ? "DEFAULT" : "CLAUDE",
                summary == null ? SecretExplanationCatalog.fallback(context) : summary,
                context.facts().stream().map(code -> new SecretExplanationResponse.Fact(code,
                        SecretExplanationCatalog.factLabel(code))).toList(),
                List.copyOf(actions), SecretExplanationCatalog.documents(context.issuer(), context.credentialType()), readiness);
    }

    private Snapshot runSnapshot(long runId, String login) {
        SecretRunStatusResponse run = runs.status(runId, login);
        Map<String, Object> status = runQueries.status(login, runId);
        var facts = new LinkedHashSet<String>();
        boolean metadata = !run.scopeResults().isEmpty() && run.scopeResults().stream()
                .allMatch(scope -> scope.contentType().endsWith("_METADATA"));
        if (metadata) {
            facts.add("METADATA_ONLY");
        } else {
            addStage(facts, "COLLECTION", run.collectionStatus());
            addStage(facts, "DETECTION", run.detectionStatus());
            addStage(facts, "VALIDATION", run.validationStatus());
        }
        if (run.coverage() == null || !run.coverage().coverageComplete()) facts.add("COVERAGE_INCOMPLETE");
        if ("PENDING".equals(run.status()) && run.attemptNo() > 0) facts.add("RETRY_SCHEDULED");
        // Only bounded reason codes cross the boundary; values and source coordinates stay here.
        var reasons = jdbc.queryForList("""
                SELECT DISTINCT reason_code FROM (
                    SELECT DISTINCT ON(credential_set_id,occurrence_id) reason_code
                    FROM secret_validation_attempts WHERE run_id=?
                    ORDER BY credential_set_id,occurrence_id,completed_at DESC,attempt_id DESC
                ) latest
                """, String.class, runId);
        for (String reason : reasons) {
            if (reason == null) continue;
            if (Set.of("INCOMPLETE_CREDENTIAL", "INCOMPLETE_PAIR").contains(reason)) facts.add("INCOMPLETE_CREDENTIAL");
            if ("MISSING_SESSION_TOKEN".equals(reason)) facts.add("MISSING_SESSION_TOKEN");
            if (Set.of("RATE_LIMITED", "RATE_BUDGET_EXHAUSTED").contains(reason)) facts.add("RATE_LIMITED");
            if (Set.of("SOURCE_UNAVAILABLE", "SOURCE_VALUE_UNAVAILABLE").contains(reason)) facts.add("SOURCE_UNAVAILABLE");
            if (Set.of("DISABLED", "VALIDATION_DISABLED", "ISSUER_NOT_ALLOWED", "SCOPE_NOT_APPROVED").contains(reason)) facts.add("VALIDATOR_DISABLED");
        }
        var links = new java.util.LinkedHashMap<String, String>();
        String history = "/secrets/history/" + runId;
        links.put("CHECK_STATUS", history);
        @SuppressWarnings("unchecked") var capabilities = (Map<String, Object>) status.get("capabilities");
        if (capabilities != null && Boolean.TRUE.equals(capabilities.get("canViewFindings"))) {
            links.put("VIEW_FINDINGS", history + "/findings");
            links.put("VIEW_LOCATIONS", "/secrets/findings?runId=" + runId);
        }
        if (capabilities != null && Boolean.TRUE.equals(capabilities.get("canRetryFailedScopes"))) {
            links.put("RETRY_FAILED_SCOPES", history + "#coverage-title");
        }
        if (capabilities != null && Boolean.TRUE.equals(capabilities.get("canManageConnection"))) {
            links.put("OPEN_SETTINGS", "/secrets/connections?connectionId=" + run.connectionId());
        }
        var context = context("SCAN", run.provider(), "MIXED", "MIXED", facts, links);
        String fingerprint = run.status() + ":" + run.attemptNo() + ":" + run.finishedAt() + ":" + run.scopeResults();
        return new Snapshot(context, Map.copyOf(links), fingerprint, true);
    }

    private Snapshot caseSnapshot(long caseId, String login) {
        var detail = cases.detail(caseId, login);
        long actor = caseRepository.actorId(login).orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
        boolean allReadable = guideRepository.allLocationsReadable(actor, caseId);
        var facts = new LinkedHashSet<String>();
        String stage = "CASE_" + detail.stage();
        if (SecretExplanationCatalog.factCodes().contains(stage)) facts.add(stage);
        facts.add(detail.actions().isEmpty() ? "NO_ACTION_RECORD" : "ACTION_RECORDED");
        if (detail.assigneeUserId() == null) facts.add("ASSIGNEE_REQUIRED");
        if (detail.occurrences().stream().anyMatch(location -> !"RESOLVED".equals(location.responseStatus()))) {
            facts.add("UNRESOLVED_LOCATIONS");
        }
        if (allReadable) {
            var guide = guideRepository.currentCase(caseId);
            if (guide.isPresent()) {
                String validation = guide.get().validationStatus();
                facts.add("VALID".equals(validation) ? "AUTH_CONFIRMED"
                        : "INVALID".equals(validation) ? "AUTH_REJECTED" : "AUTH_UNCONFIRMED");
            }
        }
        var links = new java.util.LinkedHashMap<String, String>();
        String href = "/secrets/cases/" + caseId;
        links.put("OPEN_CASE", href);
        if (detail.capabilities().canRecordAction()) links.put("RECORD_ACTION", href + "?tab=work");
        if (detail.capabilities().canRequestRevalidation()) links.put("REVALIDATE", href + "?tab=verification&check=locations");
        if (detail.assigneeUserId() == null && detail.capabilities().canReview()) links.put("ASSIGN_SELF", href + "?tab=work");
        links.put("REVIEW_CLOSURE", href + "?tab=verification&check=closure");
        var context = context("CASE", "OTHER", detail.issuer(), detail.credentialType(), facts, links);
        return new Snapshot(context, Map.copyOf(links), Long.toString(detail.version()), allReadable);
    }

    private static SecretExplanationContext context(String topic, String sourceProvider, String issuer,
                                                     String credentialType, Set<String> facts,
                                                     Map<String, String> links) {
        var documents = SecretExplanationCatalog.documents(issuer == null ? "OTHER" : issuer, credentialType).stream()
                .map(SecretExplanationResponse.Document::id).toList();
        return new SecretExplanationContext(topic, sourceProvider, issuer, credentialType,
                List.copyOf(facts), List.copyOf(links.keySet()), documents);
    }

    private static void addStage(Set<String> facts, String stage, String status) {
        String code = stage + "_" + status;
        if (SecretExplanationCatalog.factCodes().contains(code)) facts.add(code);
    }

    private record Snapshot(SecretExplanationContext context, Map<String, String> links,
                            String fingerprint, boolean aiReadable) { }
}
