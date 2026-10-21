package com.logssey.secret.policy;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import com.logssey.secret.policy.SecretPolicyContracts.*;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretPolicyRepository {
    private final JdbcTemplate jdbc;
    SecretPolicyRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    Optional<Scope> scope(long id, boolean lock) {
        return jdbc.query("""
                SELECT s.*,c.status AS connection_status,c.provider AS provider,
                    md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text) AS fingerprint,
                    COALESCE(NULLIF(to_jsonb(s)->>'safe_display_alias',''),'범위 #' || s.scope_id::text) AS safe_name
                FROM secret_connection_scopes s JOIN secret_connections c ON c.connection_id=s.connection_id
                WHERE s.scope_id=?
                """ + (lock ? " FOR UPDATE OF s" : ""), (rs, row) -> new Scope(
                rs.getLong("scope_id"),rs.getLong("connection_id"),rs.getLong("revision"),
                rs.getLong("response_origin_version"),rs.getString("response_origin"),rs.getString("content_type"),
                rs.getString("approved_ref"),rs.getString("history_limit"),rs.getString("fingerprint"),
                rs.getBoolean("enabled"),rs.getString("connection_status"),
                rs.getString("safe_display_alias")!=null?rs.getString("safe_display_alias"):com.logssey.secret.query.SecretSourceDetails.scopeLabel(rs.getString("provider"),rs.getString("approved_ref"),id)),id).stream().findFirst();
    }

    Optional<Policy> policy(long id,long version,boolean lock) {
        return jdbc.query("SELECT * FROM secret_storage_policies WHERE policy_id=? AND version=?"
                + (lock ? " FOR UPDATE" : ""), (rs,row) -> new Policy(rs.getLong("policy_id"),rs.getLong("version"),
                rs.getString("status"),rs.getString("reason_code"),rs.getString("evidence_ref"),
                rs.getLong("created_by_user_id"),rs.getObject("approved_by_user_id",Long.class),
                rs.getObject("created_at",OffsetDateTime.class),rs.getObject("valid_from",OffsetDateTime.class),
                rs.getObject("valid_until",OffsetDateTime.class),rs.getObject("approved_at",OffsetDateTime.class),
                rs.getObject("retired_at",OffsetDateTime.class)),id,version).stream().findFirst();
    }

    List<Rule> rules(long id,long version) {
        return jdbc.query("SELECT * FROM secret_storage_policy_rules WHERE policy_id=? AND policy_version=? ORDER BY rule_id",
                (rs,row) -> new Rule(rs.getLong("rule_id"),rs.getLong("connection_id"),rs.getLong("scope_id"),
                rs.getLong("scope_revision"),rs.getString("scope_fingerprint"),rs.getString("content_type"),
                rs.getString("effect"),rs.getString("path_match"),rs.getString("branch_condition"),
                rs.getString("protected_path_condition")),id,version);
    }

    Optional<ProposalState> proposal(long scopeId,long proposalId,boolean lock) {
        return jdbc.query("SELECT * FROM secret_scope_classification_proposals WHERE scope_id=? AND proposal_id=?"
                + (lock ? " FOR UPDATE" : ""), (rs,row) -> new ProposalState(rs.getLong("proposal_id"),rs.getLong("scope_id"),
                rs.getLong("expected_scope_version"),rs.getLong("scope_revision"),rs.getString("scope_fingerprint"),
                rs.getString("proposed_origin"),rs.getObject("policy_id",Long.class),rs.getObject("policy_version",Long.class),
                rs.getString("reason_code"),rs.getString("evidence_ref"),rs.getLong("proposed_by_user_id"),
                rs.getString("status"),rs.getLong("version"),rs.getObject("created_at",OffsetDateTime.class),
                rs.getString("approval_mode"),rs.getString("approval_rule_version"),rs.getObject("reviewer_user_id",Long.class)),scopeId,proposalId)
                .stream().findFirst();
    }

    Optional<ProposalState> pending(long scopeId) {
        return jdbc.query("SELECT proposal_id FROM secret_scope_classification_proposals WHERE scope_id=? AND status='PENDING_APPROVAL'",
                (rs,row) -> rs.getLong(1),scopeId).stream().findFirst().flatMap(id -> proposal(scopeId,id,false));
    }

    List<OriginDecision> history(long scopeId) {
        return jdbc.query("""
                SELECT * FROM secret_scope_origin_decisions WHERE scope_id=? ORDER BY version DESC LIMIT 100
                """, (rs,row) -> new OriginDecision(rs.getLong("decision_id"),rs.getObject("proposal_id",Long.class),
                rs.getString("decision"),rs.getString("from_origin"),rs.getString("to_origin"),rs.getString("reason_code"),
                rs.getString("evidence_ref"),rs.getLong("actor_user_id"),rs.getObject("decided_at",OffsetDateTime.class),
                rs.getLong("version"),rs.getString("approval_mode"),rs.getString("approval_rule_version")),scopeId);
    }

    Optional<OriginDecision> approvedDecision(long scopeId,long version) {
        return jdbc.query("""
                SELECT * FROM secret_scope_origin_decisions WHERE scope_id=? AND version=? AND decision='APPROVED'
                """, (rs,row) -> new OriginDecision(rs.getLong("decision_id"),rs.getObject("proposal_id",Long.class),
                rs.getString("decision"),rs.getString("from_origin"),rs.getString("to_origin"),rs.getString("reason_code"),
                rs.getString("evidence_ref"),rs.getLong("actor_user_id"),rs.getObject("decided_at",OffsetDateTime.class),
                rs.getLong("version"),rs.getString("approval_mode"),rs.getString("approval_rule_version")),scopeId,version).stream().findFirst();
    }

    Optional<Binding> binding(long scopeId) {
        return jdbc.query("""
                SELECT binding_id,policy_id,policy_version FROM secret_scope_policy_bindings
                WHERE scope_id=? AND effective_until IS NULL
                """, (rs,row) -> new Binding(rs.getLong(1),rs.getLong(2),rs.getLong(3)),scopeId).stream().findFirst();
    }

    OffsetDateTime now() { return jdbc.queryForObject("SELECT CURRENT_TIMESTAMP",OffsetDateTime.class); }

    List<String> setupReasons(long scopeId) {
        return jdbc.query("SELECT unnest(setup_reason_codes) FROM secret_scope_governance_status WHERE scope_id=?",
            (rs,row)->rs.getString(1),scopeId);
    }

    List<Reviewer> reviewers(long connectionId,long excludeUserId) {
        return jdbc.query("""
            SELECT u.user_id,u.display_name FROM dashboard_users u WHERE u.user_id<>? AND EXISTS(
              SELECT 1 FROM secret_role_grants g WHERE g.user_id=u.user_id AND g.role='SECURITY'
                AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=?))
            ORDER BY u.user_id
            """,(rs,row)->new Reviewer(rs.getLong(1),rs.getString(2)),excludeUserId,connectionId);
    }

    void audit(String event,String targetType,long targetId,long version,long actorId) {
        jdbc.update("""
                INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,safe_changes)
                VALUES (?,?,?,?,?,jsonb_build_object('version',?::bigint))
                """,event,actorId,targetType,targetId,version,version);
    }

    record Scope(long id,long connectionId,long revision,long originVersion,String origin,String contentType,
                 String approvedRef,String historyLimit,String fingerprint,boolean enabled,String connectionStatus,String safeName) {
        boolean available() { return enabled && "ACTIVE".equals(connectionStatus); }
        @Override public String toString() { return "Scope[id="+id+"]"; }
    }
    record Policy(long id,long version,String status,String reason,String evidence,long creator,Long approver,
                  OffsetDateTime createdAt,OffsetDateTime validFrom,OffsetDateTime validUntil,
                  OffsetDateTime approvedAt,OffsetDateTime retiredAt) {
        boolean usable(OffsetDateTime now) { return "ACTIVE".equals(status) && !now.isBefore(validFrom)
                && (validUntil==null || now.isBefore(validUntil)); }
    }
    record Rule(long id,long connectionId,long scopeId,long scopeRevision,String fingerprint,String contentType,
                String effect,String pathMatch,String branch,String protectedPath) {
        SafeRule safe() { return new SafeRule(id,connectionId,scopeId,contentType,effect,pathMatch); }
        @Override public String toString() { return "Rule[id="+id+",protected conditions omitted]"; }
    }
    record ProposalState(long id,long scopeId,long expectedScopeVersion,long scopeRevision,String fingerprint,
                         String origin,Long policyId,Long policyVersion,String reason,String evidence,long proposer,
                         String status,long version,OffsetDateTime createdAt,String approvalMode,String approvalRuleVersion,
                         Long reviewerUserId) { }
    record Binding(long id,long policyId,long policyVersion) { }
}
