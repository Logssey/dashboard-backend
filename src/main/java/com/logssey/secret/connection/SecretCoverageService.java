package com.logssey.secret.connection;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.run.SecretScanFactsRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Permission-filtered operations facts, independent from key/location inventories. */
@Service
@Transactional(readOnly=true)
public class SecretCoverageService {
    private static String safeConnectionName(String name, long id) {
        if (name == null || name.isBlank() || name.length() > 200 || name.chars().anyMatch(c -> c < 32 || c == 127)
                || name.matches("(?s).*(?:-----BEGIN|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|ntn_|sk-ant-|(?:AKIA|ASIA)[A-Z0-9]{16}).*"))
            return "연결 #" + id;
        return name;
    }
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final Duration scanInterval;
    private final boolean notionCollectionEnabled;
    public SecretCoverageService(JdbcTemplate jdbc, SecretAccessService access) { this(jdbc,access,"6h"); }
    public SecretCoverageService(JdbcTemplate jdbc, SecretAccessService access,
            @org.springframework.beans.factory.annotation.Value("${logssey.secret.scheduler.scan-interval:${SECRET_SCAN_INTERVAL:6h}}") String interval) {
        this(jdbc, access, interval, false);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SecretCoverageService(JdbcTemplate jdbc, SecretAccessService access,
            @org.springframework.beans.factory.annotation.Value("${logssey.secret.scheduler.scan-interval:${SECRET_SCAN_INTERVAL:6h}}") String interval,
            @org.springframework.beans.factory.annotation.Value("${logssey.secret.notion.collection.enabled:false}") boolean notionCollectionEnabled) {
        this.jdbc=jdbc;this.access=access;
        this.notionCollectionEnabled=notionCollectionEnabled;
        this.scanInterval=org.springframework.boot.convert.DurationStyle.detectAndParse(interval);
        if(scanInterval.isZero()||scanInterval.isNegative())throw new IllegalArgumentException("SCAN_INTERVAL_INVALID");
    }
    private SecretPrincipal actor(String login) {
        var a=access.requirePrincipal(login);
        boolean allowed=Boolean.TRUE.equals(jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND revoked_at IS NULL AND role IN ('SECURITY','OPERATIONS'))
            """,Boolean.class,a.userId()));
        if(!allowed)throw new ApiException(ErrorCode.FORBIDDEN);
        return a;
    }

    /** Location readers receive only that location's scope coverage, without management access. */
    public Map<String,Object> occurrenceCoverage(String login,long occurrenceId) {
        return occurrenceCoverage(access.requirePrincipal(login),occurrenceId);
    }
    public Map<String,Object> occurrenceCoverage(SecretPrincipal principal,long occurrenceId) {
        access.requireOccurrenceRead(principal,occurrenceId);
        var row=jdbc.queryForList("""
            SELECT s.scope_id,s.connection_id,s.scope_key,s.revision,s.content_type,s.response_origin,
                   s.safe_display_alias,s.enabled,c.provider,c.status,c.scope_version,c.next_due_at
            FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            JOIN secret_connections c ON c.connection_id=o.connection_id
            WHERE o.occurrence_id=?
            """,occurrenceId).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
        return coverage(row,row);
    }

    public Map<String,Object> connections(String login,String status,String origin,int page,int size) {
        validatePage(page,size); validate(status,Set.of("ALL","ACTIVE","PAUSED","ERROR")); validateOrigin(origin);
        var a=actor(login); List<Map<String,Object>> result=new ArrayList<>();
        var connections=jdbc.queryForList("SELECT connection_id,provider,display_name,status,scope_version,next_due_at FROM secret_connections ORDER BY connection_id");
        for(var c:connections) {
            long id=number(c,"connection_id");
            if(!access.canReadConnectionFacts(a,id)||!status.equals("ALL")&&!status.equals(c.get("status"))) continue;
            var scopes=currentScopes(id,origin);
            if(!origin.equals("ALL")&&scopes.isEmpty()) continue;
            Map<String,Object> item=new LinkedHashMap<>();
            item.put("connectionId",id);item.put("provider",c.get("provider"));item.put("safeDisplayAlias",safeConnectionName((String)c.get("display_name"),id));
            item.put("connectionStatus",c.get("status"));item.put("scopeRevision",c.get("scope_version"));item.put("approvedScopeCount",scopes.size());
            item.put("latestProbe",latestProbe(id));item.put("lastFullScanAttempt",fullRun(id,false));item.put("lastSuccessfulFullScan",fullRun(id,true));
            item.put("nextDueAt",time(c,"next_due_at"));item.put("activeJob",activeJob(id));
            item.put("targetSummary",scopes.stream().limit(3).map(s->com.logssey.secret.query.SecretSourceDetails.scopeLabel((String)c.get("provider"),(String)s.get("approved_ref"),number(s,"scope_id"))).toList());
            Map<String,Long> counts=new LinkedHashMap<>();
            for(var scope:scopes) {
                var cov=coverage(scope,c);var attempt=(Map<?,?>)cov.get("lastAttempt");
                String state=attempt==null?"NEVER_SCANNED":(String)attempt.get("scopeOutcome");
                counts.merge(state,1L,Long::sum);
            }
            item.put("scopeStatusCounts",counts);
            boolean operations=access.hasConnectionRole(a,id,SecretRole.OPERATIONS);
            boolean supported=Set.of("GITHUB","AWS").contains(c.get("provider"))
                    || notionCollectionEnabled&&"NOTION".equals(c.get("provider"));
            String unsupportedReason="NOTION".equals(c.get("provider"))
                    ?"NOTION_COLLECTION_DISABLED":"PROVIDER_UNSUPPORTED";
            item.put("capabilities",Map.of("canTest",operations&&supported&&"ACTIVE".equals(c.get("status")),
                "canRun",operations&&supported&&"ACTIVE".equals(c.get("status"))&&!scopes.isEmpty()&&isExecutable(id,(String)c.get("provider"))));
            item.put("testBlockedReasonCode",!operations?"OPERATIONS_ROLE_REQUIRED":!supported?unsupportedReason:!"ACTIVE".equals(c.get("status"))?"CONNECTION_PAUSED":null);
            item.put("scanBlockedReasonCode",!operations?"OPERATIONS_ROLE_REQUIRED":!supported?unsupportedReason:!"ACTIVE".equals(c.get("status"))?"CONNECTION_PAUSED":scopes.isEmpty()?"NO_SCAN_TARGETS":!isExecutable(id,(String)c.get("provider"))?"INVALID_APPROVED_SCOPE":null);
            result.add(item);
        }
        return page(result,page,size,"Connection",Map.of("status",status,"origin",origin));
    }

    public Map<String,Object> scopes(String login,long connectionId,String origin,String classificationStatus,boolean gapOnly,int page,int size) {
        validatePage(page,size);validateOrigin(origin);validate(classificationStatus,Set.of("ALL","NEEDS_REVIEW"));
        var a=actor(login);access.requireConnectionFactsRead(a,connectionId);
        var connection=jdbc.queryForList("SELECT connection_id,provider,status,scope_version,next_due_at FROM secret_connections WHERE connection_id=?",connectionId)
            .stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
        List<Map<String,Object>> rows=new ArrayList<>();
        for(var scope:currentScopes(connectionId,origin)) {
            if(classificationStatus.equals("NEEDS_REVIEW")&&!Boolean.TRUE.equals(jdbc.queryForObject("SELECT needs_review FROM secret_scope_governance_status WHERE scope_id=?",Boolean.class,scope.get("scope_id"))))continue;
            var cov=coverage(scope,connection);
            if(gapOnly&&((List<?>)cov.get("gapReasonCodes")).isEmpty())continue;
            rows.add(scopeItem(scope,connection,cov,a));
        }
        return page(rows,page,size,"Scope",Map.of("origin",origin,"classificationStatus",classificationStatus,"gapOnly",gapOnly));
    }

    public Map<String,Object> gaps(String login,String origin,String source,Long connectionId,String snapshotId,int page,int size) {
        validatePage(page,size);validateOrigin(origin);validate(source,Set.of("ALL","GITHUB","AWS","NOTION","KUBERNETES"));
        if(connectionId!=null&&connectionId<=0)throw new ApiException(ErrorCode.INVALID_INPUT);
        if(snapshotId!=null&&!snapshotId.isBlank())throw new ApiException(ErrorCode.INVALID_INPUT);
        var a=actor(login);List<Map<String,Object>> rows=new ArrayList<>();
        for(var c:jdbc.queryForList("SELECT connection_id,provider,status,scope_version,next_due_at FROM secret_connections ORDER BY connection_id")) {
            long id=number(c,"connection_id");
            if(connectionId!=null&&connectionId!=id||!source.equals("ALL")&&!source.equals(c.get("provider"))||!access.canReadConnectionFacts(a,id))continue;
            for(var s:currentScopes(id,origin)) {
                var cov=coverage(s,c);
                if(!((List<?>)cov.get("gapReasonCodes")).isEmpty()) {
                    var item=scopeItem(s,c,cov,a);
                    item.put("whyHereCode","COVERAGE_GAP");item.put("nextActionCode","RESTORE_SCAN");
                    item.put("taskGuidance",com.logssey.secret.query.SecretTaskGuidance.build("COVERAGE_GAP","RESTORE_SCAN",
                        Map.of("type","SCOPE","id",number(s,"scope_id"),"connectionId",id),access.hasConnectionRole(a,id,SecretRole.OPERATIONS),
                        "ROLE_REQUIRED","OPERATIONS",cov.get("lastSuccessfulScan")==null?null:((Map<?,?>)cov.get("lastSuccessfulScan")).get("finishedAt"),
                        null,null,(List<String>)cov.get("gapReasonCodes"),List.of("COVERAGE_BLOCKED")));
                    rows.add(item);
                }
            }
        }
        return page(rows,page,size,"Scope",Map.of("origin",origin,"source",source));
    }

    private boolean isExecutable(long connectionId,String provider) {
        if ("NOTION".equals(provider)) {
            String valid=com.logssey.secret.notion.NotionScopeSql.predicate("s");
            return notionCollectionEnabled&&Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM secret_connections WHERE connection_id=? AND auth_ref='notion-internal:default')"
                +" AND EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled)"
                +" AND NOT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled AND ("+valid+") IS NOT TRUE)",
                Boolean.class,connectionId,connectionId,connectionId));
        }
        String valid=provider.equals("AWS")?com.logssey.secret.run.AwsScopeSql.predicate("s"):
            "(s.content_type='GITHUB_REPOSITORY_FILES' AND s.history_limit='CURRENT_COMMIT_ONLY' AND s.approved_ref ~ '^github://[^/]+/[^/]+/[^/]+/([^/?#]+/)*$')";
        String sql="SELECT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled)"
            +" AND NOT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled AND ("+valid+") IS NOT TRUE)";
        if(provider.equals("AWS"))sql+=" AND EXISTS(SELECT 1 FROM secret_connections c WHERE c.connection_id=? AND (c.auth_ref ~ '^aws-profile:[A-Za-z0-9._-]{1,100}$' OR c.auth_ref='aws-workload:default'))";
        return Boolean.TRUE.equals(provider.equals("AWS")?jdbc.queryForObject(sql,Boolean.class,connectionId,connectionId,connectionId):jdbc.queryForObject(sql,Boolean.class,connectionId,connectionId));
    }

    private List<Map<String, Object>> currentScopes(long connectionId, String origin) {
        return jdbc.queryForList(
                """
SELECT scope_id,connection_id,scope_key,revision,content_type,history_limit,response_origin,response_origin_version,safe_display_alias,alias_version,enabled,approved_ref,
    md5(jsonb_build_array(content_type,approved_ref,history_limit)::text) AS scope_fingerprint
FROM secret_connection_scopes WHERE connection_id=? AND enabled
    AND (?='ALL' OR response_origin=?) ORDER BY scope_id
""",
                connectionId,
                origin,
                origin);
    }

    private Map<String, Object> scopeItem(
            Map<String, Object> s,
            Map<String, Object> c,
            Map<String, Object> coverage,
            SecretPrincipal actor) {
        Map<String, Object> item = new LinkedHashMap<>();
        long id = number(s, "scope_id");
        item.put("scopeId", id);
        item.put("connectionId", c.get("connection_id"));
        item.put("scopeRevision", s.get("revision"));
        item.put("source", c.get("provider"));
        item.put("contentType", safeType((String) s.get("content_type")));
        item.put("githubTarget", com.logssey.secret.query.SecretSourceDetails.githubTarget(
                (String)c.get("provider"),(String)s.get("content_type"),(String)s.get("approved_ref")));
        item.put("origin", s.get("response_origin"));
        item.put("connectionStatus", c.get("status"));
        item.put(
                "safeDisplayAlias",
                s.get("safe_display_alias") == null
                        ? com.logssey.secret.query.SecretSourceDetails.scopeLabel(
                                (String) c.get("provider"), (String) s.get("approved_ref"), id)
                        : s.get("safe_display_alias"));
        item.put("customSafeDisplayAlias", s.get("safe_display_alias"));
        item.put("aliasVersion", s.get("alias_version"));
        boolean canEditAlias =
                access.hasConnectionRole(actor, number(c, "connection_id"), SecretRole.OPERATIONS);
        boolean security =
                access.hasConnectionRole(actor, number(c, "connection_id"), SecretRole.SECURITY);
        item.put("coverage", coverage);
        var reasons =
                jdbc.query(
                        "SELECT unnest(setup_reason_codes) FROM secret_scope_governance_status WHERE"
                                + " scope_id=?",
                        (rs, n) -> rs.getString(1),
                        id);
        item.put("setupReasonCodes", reasons);
        var pending =
                jdbc.queryForList(
                        """
SELECT q.*,q.policy_id IS NULL OR EXISTS(SELECT 1 FROM secret_storage_policies p
    WHERE p.policy_id=q.policy_id AND p.version=q.policy_version AND p.status='ACTIVE'
        AND p.valid_from<=now() AND (p.valid_until IS NULL OR p.valid_until>now())) AS policy_usable
FROM secret_scope_classification_proposals q WHERE q.scope_id=? AND q.status='PENDING_APPROVAL'
""",
                        id);
        var proposal = pending.isEmpty() ? null : pending.getFirst();
        boolean proposalCurrent =
                proposal != null
                        && Objects.equals(proposal.get("scope_revision"), s.get("revision"))
                        && Objects.equals(
                                proposal.get("expected_scope_version"), s.get("response_origin_version"))
                        && Objects.equals(proposal.get("scope_fingerprint"), s.get("scope_fingerprint"))
                        && Boolean.TRUE.equals(proposal.get("policy_usable"));
        boolean approve =
                security
                        && proposalCurrent
                        && number(proposal, "proposed_by_user_id") != actor.userId()
                        && (proposal.get("reviewer_user_id") == null
                                || number(proposal, "reviewer_user_id") == actor.userId());
        boolean available = "ACTIVE".equals(c.get("status")) && Boolean.TRUE.equals(s.get("enabled"));
        boolean supported =
                "GITHUB".equals(c.get("provider"))
                        ? com.logssey.secret.response.SecretGithubScopePolicy.approved(
                                        (String) s.get("content_type"),
                                        (String) s.get("history_limit"),
                                        (String) s.get("approved_ref"))
                                && !s.get("approved_ref").toString().contains("..")
                                && !s.get("approved_ref").toString().contains("\\")
                        : "NOTION".equals(c.get("provider"))
                                ? com.logssey.secret.notion.NotionScopeSql.valid(
                                        (String)s.get("content_type"),(String)s.get("approved_ref"),(String)s.get("history_limit"))
                                : "AWS".equals(c.get("provider"))
                                && Boolean.TRUE.equals(
                                        jdbc.queryForObject(
                                                "SELECT "
                                                        + com.logssey.secret.run.AwsScopeSql.predicate("s")
                                                        + " FROM secret_connection_scopes s WHERE scope_id=?",
                                                Boolean.class,
                                                id));
        boolean valueScope =
                Set.of(
                                "GITHUB_REPOSITORY_FILES",
                                "AWS_SECRETS_MANAGER_VALUE",
                                "AWS_SSM_PARAMETER_VALUE",
                                "AWS_S3_OBJECT_CONTENT", "NOTION_PAGE_CONTENT")
                        .contains(s.get("content_type"));
        String blocked =
                !available
                        ? "CONNECTION_PAUSED"
                        : !supported ? "SOURCE_CONFIGURATION_UNSUPPORTED" : !security ? "ROLE_REQUIRED" : null;
        item.put(
                "setupState",
                !available
                        ? "PAUSED"
                        : !supported ? "UNSUPPORTED" : proposal != null ? "PENDING_REVIEW" : "READY");
        item.put("setupBlockedReasonCode", blocked);
        item.put(
                "capabilities",
                Map.of(
                        "canEditAlias",
                        canEditAlias,
                        "canClassifySource",
                        security && available && supported && proposal == null,
                        "canConfigureStoragePolicy",
                        security && available && supported && valueScope,
                        "canReviewClassification",
                        approve && available && supported));
        var task =
                com.logssey.secret.query.SecretTaskGuidance.scope(
                        id,
                        number(c, "connection_id"),
                        reasons,
                        security && available && supported,
                        approve && available && supported,
                        proposal == null ? null : time(proposal, "created_at"));
        if (blocked != null) {
            task.put("canExecute", false);
            task.put("blockedReasonCode", blocked);
        }
        item.put("taskGuidance", task);
        return item;
    }

    private Map<String,Object> coverage(Map<String,Object> s,Map<String,Object> c) {
        long scopeId=number(s,"scope_id"),revision=number(s,"revision");
        var all=jdbc.queryForList("""
            SELECT o.run_id,o.scope_revision,o.scope_outcome,o.requested_at,o.finished_at,o.run_finished_at,o.job_status,r.result_status
            FROM secret_scope_outcomes o JOIN secret_connection_scopes historical ON historical.scope_id=o.scope_id
            JOIN secret_scan_runs r ON r.run_id=o.run_id
            WHERE historical.connection_id=? AND historical.scope_key=? AND o.job_kind='FULL_SCAN'
            ORDER BY o.requested_at DESC,o.run_id DESC
            """,c.get("connection_id"),s.get("scope_key"));
        var latest=all.stream().filter(x->Objects.equals(x.get("scope_revision"),revision)).findFirst().orElse(null);
        var success=all.stream().filter(x->Objects.equals(x.get("scope_revision"),revision)&&"SUCCEEDED".equals(x.get("scope_outcome"))&&"SUCCEEDED".equals(x.get("job_status"))).findFirst().orElse(null);
        List<String> reasons=new ArrayList<>();
        if(latest==null)reasons.add(all.isEmpty()?"NEVER_SCANNED":"REVISION_UNCHECKED");
        else if(success==null)reasons.add("NEVER_SCANNED");
        else if(Set.of("PARTIAL","FAILED","SKIPPED","CANCELLED","UNKNOWN").contains(latest.get("scope_outcome"))) reasons.add("LAST_ATTEMPT_INCOMPLETE");
        if(latest!=null&&Set.of("PENDING","RUNNING").contains(latest.get("scope_outcome"))) {
            var terminal=all.stream().filter(x->Objects.equals(x.get("scope_revision"),revision)
                &&!Set.of("PENDING","RUNNING").contains(x.get("scope_outcome"))).findFirst().orElse(null);
            if(terminal!=null&&!"SUCCEEDED".equals(terminal.get("scope_outcome")))reasons.add("LAST_ATTEMPT_INCOMPLETE");
        }
        var next=time(c,"next_due_at"); boolean paused=!"ACTIVE".equals(c.get("status"))||Boolean.FALSE.equals(s.get("enabled"));
        // next_due_at can advance while a due scan is merely queued. No success ever remains a gap.
        boolean overdue=next!=null&&(next.isBefore(OffsetDateTime.now(ZoneOffset.UTC))
            ||success!=null&&time(success,"finished_at")!=null&&time(success,"finished_at").plus(scanInterval).isBefore(OffsetDateTime.now(ZoneOffset.UTC)));
        if(overdue)reasons.add("OVERDUE");if(!"ACTIVE".equals(c.get("status")))reasons.add("CONNECTION_PAUSED");
        if(Boolean.FALSE.equals(s.get("enabled")))reasons.add("SCOPE_DISABLED");
        boolean running=jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_scope_outcomes WHERE scope_id=? AND scope_revision=?
                AND job_kind='FULL_SCAN' AND job_status IN ('PENDING','LEASED'))
            """,Boolean.class,scopeId,revision);
        Map<String,Object> result=new LinkedHashMap<>();result.put("scopeId",scopeId);result.put("scopeRevision",revision);
        result.put("lastAttempt",attempt(latest));result.put("lastSuccessfulScan",attempt(success));result.put("nextDueAt",next);
        result.put("isPaused",paused);result.put("isRunning",running);
        result.put("freshness",latest==null?"NEVER_SCANNED":next==null?"NOT_SCHEDULED":overdue?"OVERDUE":"CURRENT");
        result.put("gapReasonCodes",reasons);return result;
    }

    private Map<String,Object> fullRun(long connectionId,boolean success) {
        String query="""
            SELECT r.run_id,r.requested_at,r.finished_at,j.status AS job_status,r.result_status
            FROM secret_scan_runs r JOIN secret_jobs j ON j.job_id=r.job_id
            JOIN secret_connections c ON c.connection_id=r.connection_id
            WHERE r.connection_id=? AND j.kind='FULL_SCAN'
            """;
        if(success)query+="""
             AND j.status='SUCCEEDED' AND r.scope_version=c.scope_version
             AND EXISTS(SELECT 1 FROM secret_scope_outcomes o WHERE o.run_id=r.run_id)
             AND NOT EXISTS(SELECT 1 FROM secret_scope_outcomes o WHERE o.run_id=r.run_id AND o.scope_outcome<>'SUCCEEDED')
             AND (SELECT count(*) FROM secret_run_scopes x WHERE x.run_id=r.run_id)=
                 (SELECT count(*) FROM secret_connection_scopes s WHERE s.connection_id=c.connection_id AND s.enabled)
             AND NOT EXISTS(SELECT 1 FROM secret_run_scopes x JOIN secret_connection_scopes s ON s.scope_id=x.scope_id
                    WHERE x.run_id=r.run_id AND (NOT s.enabled OR x.scope_revision IS DISTINCT FROM s.revision))
            """;
        var list=jdbc.queryForList(query+" ORDER BY r.requested_at DESC,r.run_id DESC LIMIT 1",connectionId);
        if(list.isEmpty())return null;
        var r=list.getFirst();Map<String,Object> result=new LinkedHashMap<>();result.put("runId",r.get("run_id"));
        result.put("status",display((String)r.get("job_status"),(String)r.get("result_status")));
        result.put("requestedAt",time(r,"requested_at"));result.put("finishedAt",time(r,"finished_at"));return result;
    }

    private Map<String,Object> latestProbe(long id) {
        var list=jdbc.queryForList("SELECT probe_id,check_kind,status,reason_code,checked_at FROM secret_connection_probes WHERE connection_id=? ORDER BY checked_at DESC,probe_id DESC LIMIT 1",id);
        if(list.isEmpty())return null;var p=list.getFirst();Map<String,Object> result=new LinkedHashMap<>();
        result.put("probeId",p.get("probe_id"));result.put("checkKind",p.get("check_kind"));result.put("status",p.get("status"));
        result.put("reasonCode",safeProbeCode((String)p.get("reason_code")));result.put("checkedAt",time(p,"checked_at"));return result;
    }
    private Map<String,Object> activeJob(long id) {
        var list=jdbc.queryForList("""
            SELECT r.run_id,j.status,CASE WHEN j.status='PENDING' THEN GREATEST(j.available_at,(
                SELECT max(retry.source_retry_at) FROM secret_connections source
                JOIN secret_connections retry ON retry.provider='NOTION' AND retry.auth_ref=source.auth_ref
                WHERE source.connection_id=j.connection_id AND source.provider='NOTION'
            )) ELSE j.available_at END AS available_at
            FROM secret_jobs j JOIN secret_scan_runs r ON r.job_id=j.job_id
            WHERE j.connection_id=? AND j.kind='FULL_SCAN' AND j.status IN ('PENDING','LEASED') ORDER BY j.job_id LIMIT 1
            """,id);
        if(list.isEmpty())return null;var row=list.getFirst();return Map.of("runId",row.get("run_id"),"status",row.get("status"),"availableAt",time(row,"available_at"));
    }
    private static Map<String,Object> attempt(Map<String,Object> r) {
        if(r==null)return null;Map<String,Object> result=new LinkedHashMap<>();result.put("runId",r.get("run_id"));
        result.put("scopeOutcome",r.get("scope_outcome"));result.put("status",r.get("scope_outcome"));result.put("requestedAt",time(r,"requested_at"));
        result.put("runStatus",display((String)r.get("job_status"),(String)r.get("result_status")));
        result.put("finishedAt",time(r,"finished_at"));return result;
    }
    private static Map<String,Object> page(List<Map<String,Object>> rows,int page,int size,String unit,Map<String,Object> filters) {
        int from=(int)Math.min((long)page*size,rows.size()),to=Math.min(from+size,rows.size());
        Map<String,Object> result=new LinkedHashMap<>();result.put("items",rows.subList(from,to));result.put("total",rows.size());
        result.put("page",page);result.put("size",size);result.put("unit",unit);result.put("filters",filters);
        result.put("asOf",OffsetDateTime.now(ZoneOffset.UTC));result.put("snapshotId",null);result.put("expiresAt",null);result.put("readConsistency","LIVE");return result;
    }
    private static long number(Map<String,Object> r,String key) { return ((Number)r.get(key)).longValue(); }
    private static OffsetDateTime time(Map<String,Object> r,String key) { var x=r.get(key);return x instanceof OffsetDateTime o?o:x instanceof java.sql.Timestamp t?t.toInstant().atOffset(ZoneOffset.UTC):null; }
    private static String display(String job,String result){return switch(job){case "LEASED"->"RUNNING";case "SUCCEEDED"->result;default->job;};}
    private static void validatePage(int page,int size){if(page<0||page>1_000_000||size<1||size>100)throw new ApiException(ErrorCode.INVALID_INPUT);}
    private static void validateOrigin(String origin){validate(origin,Set.of("ALL","PRODUCTION","TEST","UNCLASSIFIED"));}
    private static void validate(String value,Set<String> allowed){if(value==null||!allowed.contains(value))throw new ApiException(ErrorCode.INVALID_INPUT);}
    private static String safeType(String type){return Set.of("GITHUB_REPOSITORY_FILES","IAM_ACCESS_KEY_METADATA","AWS_SECRETS_MANAGER_METADATA","AWS_SSM_PARAMETER_METADATA","AWS_S3_BUCKET_METADATA","AWS_SECRETS_MANAGER_VALUE","AWS_SSM_PARAMETER_VALUE","AWS_S3_OBJECT_CONTENT","NOTION_PAGE_CONTENT").contains(type)?type:"UNSUPPORTED";}
    private static String safeProbeCode(String code){return code==null?null:Set.of("INVALID_APPROVED_SCOPE","AWS_ACCOUNT_MISMATCH","AWS_ACCESS_DENIED","AWS_RATE_LIMITED","AWS_UNAVAILABLE","GITHUB_APP_UNAVAILABLE","GITHUB_ACCESS_DENIED","GITHUB_RATE_LIMITED","GITHUB_UNAVAILABLE","NOTION_COLLECTION_DISABLED","NOTION_CREDENTIALS_UNAVAILABLE","NOTION_ACCESS_DENIED","NOTION_RATE_LIMITED","NOTION_UNAVAILABLE").contains(code)?code:"PROBE_UNAVAILABLE";}
}
