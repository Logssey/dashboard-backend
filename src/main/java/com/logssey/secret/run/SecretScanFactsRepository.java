package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecretScanFactsRepository {
    private final JdbcTemplate jdbc;
    public SecretScanFactsRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    public List<SecretRunScopeResultResponse> scopes(long runId) {
        return jdbc.query("""
            SELECT o.*, s.content_type AS fallback_type, s.approved_ref,r.excluded_object_count
            FROM secret_scope_outcomes o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            JOIN secret_run_scopes r ON r.run_scope_id=o.run_scope_id
            WHERE o.run_id=? ORDER BY o.run_scope_id
            """, (rs,n) -> {
            boolean recorded=rs.getObject("evidence_version")!=null;
            String type=recorded?rs.getString("snapshot_content_type"):rs.getString("fallback_type");
            if (!Set.of("GITHUB_REPOSITORY_FILES","IAM_ACCESS_KEY_METADATA","AWS_SECRETS_MANAGER_METADATA",
                "AWS_SSM_PARAMETER_METADATA","AWS_S3_BUCKET_METADATA","AWS_SECRETS_MANAGER_VALUE",
                "AWS_SSM_PARAMETER_VALUE","AWS_S3_OBJECT_CONTENT","NOTION_PAGE_CONTENT").contains(type)) type="UNSUPPORTED";
            var at=rs.getObject("finished_at",OffsetDateTime.class);
            String collection=rs.getString("collection_status");
            String failure=safeCode(rs.getString("failure_code")==null?rs.getString("unsupported_reason"):rs.getString("failure_code"));
            String outcome=rs.getString("scope_outcome");
            if(failure==null&&outcome.equals("UNKNOWN"))failure=recorded?"STAGE_NOT_RECORDED":"EVIDENCE_NOT_RECORDED";
            String alias=rs.getString("safe_display_alias");
            long scopeId=rs.getLong("scope_id");
            return new SecretRunScopeResultResponse(rs.getLong("run_scope_id"),type,SecretRunService.region(type,rs.getString("approved_ref")),collection,
                rs.getObject("object_count",Long.class),failure,scopeId,rs.getObject("scope_revision",Long.class),
                alias==null?"범위 #"+scopeId:alias,outcome,
                new SecretRunScopeResultResponse.Stage(collection,failure,true,at),
                new SecretRunScopeResultResponse.Stage(recorded?Objects.requireNonNullElse(rs.getString("detection_stage_status"),"UNKNOWN"):"UNKNOWN",
                    stageReason(recorded,rs.getString("detection_stage_status"),rs.getString("detection_reason_code")),!type.endsWith("_METADATA"),at),
                new SecretRunScopeResultResponse.Stage(recorded?Objects.requireNonNullElse(rs.getString("validation_stage_status"),"UNKNOWN"):"UNKNOWN",
                    stageReason(recorded,rs.getString("validation_stage_status"),rs.getString("validation_reason_code")),rs.getBoolean("validation_required"),at),
                rs.getObject("started_at",OffsetDateTime.class),at,false,rs.getInt("excluded_object_count"));
        },runId);
    }

    public SecretRunCoverageResponse runCoverage(long runId) {
        var scopes=scopes(runId);
        Map<String,Long> counts=new LinkedHashMap<>();
        for(String state:List.of("PENDING","RUNNING","SUCCEEDED","PARTIAL","FAILED","SKIPPED","CANCELLED","UNKNOWN")) counts.put(state,0L);
        scopes.forEach(s->counts.compute(s.scopeOutcome(),(k,v)->v==null?1:v+1));
        long unknown=counts.get("UNKNOWN");
        boolean legacy=scopes.stream().anyMatch(s->s.scopeRevision()==null);
        long finished=scopes.stream().filter(s->Set.of("SUCCEEDED","PARTIAL","FAILED","SKIPPED","CANCELLED").contains(s.scopeOutcome())).count();
        long incomplete=counts.get("PARTIAL")+counts.get("FAILED")+counts.get("SKIPPED")+counts.get("CANCELLED");
        boolean complete=!legacy&&!scopes.isEmpty()&&counts.get("SUCCEEDED")==scopes.size();
        var result=jdbc.queryForMap("""
            SELECT count(f.finding_id) AS findings, count(DISTINCT o.credential_set_id) AS credentials,
                count(DISTINCT o.credential_set_id) FILTER(WHERE c.first_seen_run_id=f.run_id) AS new_credentials,
                count(*) FILTER(WHERE c.first_seen_run_id IS NULL) AS legacy_credentials
            FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
            JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
            WHERE f.run_id=? AND c.component_state<>'METADATA_ONLY'
            """,runId);
        long findings=((Number)result.get("findings")).longValue();
        long credentials=((Number)result.get("credentials")).longValue();
        long newCredentials=((Number)result.get("new_credentials")).longValue();
        boolean legacyFirstSeen=((Number)result.get("legacy_credentials")).longValue()>0;
        boolean metadataOnly=scopes.stream().allMatch(s->s.contentType().endsWith("_METADATA"));
        boolean linkedCounts=!metadataOnly&&(complete||findings>0);
        var revalidation=jdbc.query("SELECT case_id, occurrence_id FROM secret_case_revalidations WHERE run_id=?",
            (rs,n)->new SecretRunCoverageResponse.Revalidation(rs.getLong(1),rs.getLong(2)),runId).stream().findFirst().orElse(null);
        var connection=jdbc.queryForMap("SELECT r.connection_id,c.provider FROM secret_scan_runs r JOIN secret_connections c ON c.connection_id=r.connection_id WHERE r.run_id=?",runId);
        return new SecretRunCoverageResponse(legacy?null:counts.get("SUCCEEDED"),finished,legacy?null:incomplete,
            scopes.size()-counts.get("SUCCEEDED"),counts,legacy?"LEGACY_UNAVAILABLE":unknown>0?"RESULT_LINK_UNAVAILABLE":"AVAILABLE",
            linkedCounts?findings:null,linkedCounts?credentials:null,!metadataOnly&&revalidation==null&&linkedCounts&&!legacyFirstSeen?newCredentials:null,
            metadataOnly||revalidation!=null?"NOT_APPLICABLE":legacyFirstSeen?"LEGACY_UNAVAILABLE":linkedCounts?null:"RESULT_LINK_UNAVAILABLE",complete,"Scope",OffsetDateTime.now(java.time.ZoneOffset.UTC),revalidation,(String)connection.get("provider"),"연결 #"+connection.get("connection_id"));
    }

    private static String stageReason(boolean recorded,String status,String reason) {
        if(!recorded)return "EVIDENCE_NOT_RECORDED";
        return status==null?"STAGE_NOT_RECORDED":safeCode(reason);
    }

    public static String safeCode(String code) {
        if(code==null) return null;
        if(Set.of("NOT_APPLICABLE_METADATA","NO_OBJECTS","DETECTION_NOT_RUN","VALIDATION_ATTEMPT_FAILED",
            "VALIDATION_INCONCLUSIVE","VALIDATION_DISABLED","SYNTHETIC_FIXTURE","NO_CANDIDATES",
            "NO_SUPPORTED_VALIDATOR","EVIDENCE_NOT_RECORDED").contains(code)) return code;
        return SecretRunService.safeFailureCode(code);
    }
}
