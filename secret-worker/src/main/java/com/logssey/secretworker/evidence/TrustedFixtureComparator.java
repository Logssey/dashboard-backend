package com.logssey.secretworker.evidence;

import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Internal worker-only comparator. Identity bytes are never returned or logged. */
public final class TrustedFixtureComparator {
    private final JdbcTemplate jdbc;
    public TrustedFixtureComparator(JdbcTemplate jdbc){this.jdbc=jdbc;}

    /** Caller holds the completed job's transaction/lease fence. Only exact protected identities count. */
    public void compareRun(long runId,OffsetDateTime observedAt){
        var keys=jdbc.query("""
            SELECT DISTINCT c.credential_set_id,c.issuer,c.credential_type,c.fingerprint_key_version,c.fingerprint,
                o.scope_id,s.revision,rs.run_scope_id
            FROM secret_current_valid_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
            JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
            JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            JOIN secret_run_scopes rs ON rs.run_id=f.run_id AND rs.scope_id=o.scope_id
            WHERE f.run_id=? AND c.component_state='CONFIRMED' AND s.response_origin='TEST'
            ORDER BY c.credential_set_id,o.scope_id
            """,(rs,n)->new Key(rs.getLong(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getBytes(5),rs.getLong(6),rs.getLong(7),rs.getLong(8)),runId);
        for(var key:keys){
            var manifests=jdbc.queryForList("""
                SELECT DISTINCT m.manifest_id,m.version,m.allow_auto_attestation FROM secret_fixture_manifests m
                JOIN secret_fixture_manifest_identities i ON i.manifest_id=m.manifest_id AND i.manifest_version=m.version
                WHERE i.scope_id=? AND i.scope_revision=? AND m.approval_status='APPROVED' AND m.revoked_at IS NULL
                  AND m.valid_from<=CURRENT_TIMESTAMP AND (m.valid_until IS NULL OR m.valid_until>CURRENT_TIMESTAMP)
                """,key.scopeId(),key.revision());
            for(var manifest:manifests){
                long id=((Number)manifest.get("manifest_id")).longValue(),version=((Number)manifest.get("version")).longValue();
                var expected=jdbc.query("""
                    SELECT protected_fingerprint FROM secret_fixture_manifest_identities
                    WHERE manifest_id=? AND manifest_version=? AND scope_id=? AND scope_revision=?
                     AND issuer=? AND credential_type=? AND fingerprint_key_version=?
                    """,(rs,n)->rs.getBytes(1),id,version,key.scopeId(),key.revision(),key.issuer(),key.type(),key.keyVersion());
                boolean match=expected.stream().anyMatch(bytes->MessageDigest.isEqual(bytes,key.fingerprint()));
                expected.forEach(bytes->Arrays.fill(bytes,(byte)0));
                Long evidence=jdbc.queryForObject("""
                    INSERT INTO secret_fixture_match_evidence(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,
                        run_scope_id,comparator_id,comparator_version,match_result,protected_match_ref,observed_at)
                    VALUES(?,?,?,?,?,?,'LOGSSEY_PROTECTED_IDENTITY','1',?,?,?)
                    ON CONFLICT(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,run_scope_id)
                    DO UPDATE SET match_result=secret_fixture_match_evidence.match_result RETURNING match_evidence_id
                    """,Long.class,key.id(),key.scopeId(),key.revision(),id,version,key.runScopeId(),match?"MATCH":"NO_MATCH",
                    "protected-match:"+UUID.randomUUID(),observedAt);
                if(match&&Boolean.TRUE.equals(manifest.get("allow_auto_attestation")))jdbc.update("""
                    INSERT INTO secret_test_fixture_attestations(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,
                        match_evidence_id,confirmation_source,status,confirmed_at)
                    SELECT ?,?,?,?,?,?,'APPROVED_POLICY','ACTIVE',?
                    WHERE NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials WHERE credential_set_id=?)
                    ON CONFLICT(match_evidence_id) DO NOTHING
                    """,key.id(),key.scopeId(),key.revision(),id,version,evidence,observedAt,key.id());
            }
            Arrays.fill(key.fingerprint(),(byte)0);
        }
    }
    private record Key(long id,String issuer,String type,String keyVersion,byte[] fingerprint,long scopeId,long revision,long runScopeId){
        @Override public String toString(){return "ProtectedFixtureKey[id="+id+"]";}
    }
}
