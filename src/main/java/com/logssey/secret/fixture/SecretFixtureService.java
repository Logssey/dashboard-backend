package com.logssey.secret.fixture;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** General HTTP commands can review an internal match, but can never create a manifest or match. */
@Service @Transactional(readOnly=true)
public class SecretFixtureService {
 private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretCommandExecutor commands;
 public SecretFixtureService(JdbcTemplate jdbc,SecretAccessService access,SecretCommandExecutor commands){this.jdbc=jdbc;this.access=access;this.commands=commands;}
 public record Attest(Long scopeId,Long expectedScopeVersion,Long manifestId,Long manifestVersion,Long matchEvidenceId,String idempotencyKey){}

 public Map<String,Object> list(String login,long key){
  var actor=access.requirePrincipal(login);requireKeyRead(actor,key);List<Map<String,Object>> items=new ArrayList<>();
  for(var r:jdbc.queryForList("""
   SELECT a.*,s.connection_id,EXISTS(SELECT 1 FROM secret_current_fixture_attestations current WHERE current.attestation_id=a.attestation_id) AS current_valid
   FROM secret_test_fixture_attestations a JOIN secret_connection_scopes s ON s.scope_id=a.scope_id WHERE a.credential_set_id=? ORDER BY a.attestation_id DESC
   """,key)){
   if(!access.hasConnectionRole(actor,number(r,"connection_id"),SecretRole.SECURITY))continue;
   Map<String,Object> item=attestation(r);item.put("isCurrentlyValid",r.get("current_valid"));items.add(item);
  }
  List<Map<String,Object>> matches=new ArrayList<>();
  for(var r:eligibleMatches(key))if(access.hasConnectionRole(actor,number(r,"connection_id"),SecretRole.SECURITY)){
   Map<String,Object> item=new LinkedHashMap<>();for(String name:List.of("match_evidence_id","scope_id","scope_revision","manifest_id","manifest_version")){
    String target=switch(name){case "match_evidence_id"->"matchEvidenceId";case "scope_id"->"scopeId";case "scope_revision"->"scopeRevision";case "manifest_id"->"manifestId";default->"manifestVersion";};item.put(target,r.get(name));}
   item.put("expectedScopeVersion",r.get("scope_revision"));item.put("originVersion",r.get("response_origin_version"));item.put("observedAt",time(r,"observed_at"));matches.add(item);
  }
  return Map.of("items",items,"eligibleMatches",matches,"fixtureStatus",visibleFixtureStatus(actor,key),"capabilities",Map.of("canAttest",!matches.isEmpty()));
 }
 public Map<String,Object> attest(String login,long key,Attest r){
  if(r==null||r.scopeId()==null||r.scopeId()<=0||r.manifestId()==null||r.manifestId()<=0||r.manifestVersion()==null||r.manifestVersion()<=0||r.matchEvidenceId()==null||r.matchEvidenceId()<=0)throw new ApiException(ErrorCode.INVALID_INPUT);
  var actor=access.requirePrincipal(login);long connection=scopeConnection(r.scopeId());access.requireConnectionRole(actor,connection,SecretRole.SECURITY);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.FIXTURE_ATTEST,r.idempotencyKey(),digest(key,r.scopeId(),r.expectedScopeVersion(),r.manifestId(),r.manifestVersion(),r.matchEvidenceId()),
   ()->access.requireConnectionRole(actor,scopeConnection(r.scopeId()),SecretRole.SECURITY),()->{
    var scope=jdbc.queryForList("SELECT revision,response_origin FROM secret_connection_scopes WHERE scope_id=? FOR UPDATE",r.scopeId()).getFirst();
    SecretCommandExecutor.requireExpectedVersion(r.expectedScopeVersion(),number(scope,"revision"));
    jdbc.queryForList("SELECT credential_set_id FROM secret_credential_sets WHERE credential_set_id=? FOR UPDATE",key);
    if(!scope.get("response_origin").equals("TEST"))throw new ApiException(ErrorCode.CONFLICT);
    var eligible=eligibleMatches(key).stream().filter(e->Objects.equals(e.get("match_evidence_id"),r.matchEvidenceId())
       &&Objects.equals(e.get("scope_id"),r.scopeId())&&Objects.equals(e.get("manifest_id"),r.manifestId())&&Objects.equals(e.get("manifest_version"),r.manifestVersion())).findFirst();
    if(eligible.isEmpty())throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    long id=jdbc.queryForObject("""
     INSERT INTO secret_test_fixture_attestations(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,match_evidence_id,
         confirmed_by_user_id,confirmation_source,status,confirmed_at)
     VALUES(?,?,?,?,?,?,?,'HUMAN','ACTIVE',clock_timestamp()) RETURNING attestation_id
     """,Long.class,key,r.scopeId(),r.expectedScopeVersion(),r.manifestId(),r.manifestVersion(),r.matchEvidenceId(),actor.userId());
    return new SecretCommandResult(id,0,SecretCommandResult.Status.ATTESTED);
   });return mutation("attestationId",result);
 }
 private List<Map<String,Object>> eligibleMatches(long key){return jdbc.queryForList("""
  SELECT e.match_evidence_id,e.scope_id,e.scope_revision,e.manifest_id,e.manifest_version,e.observed_at,s.connection_id,s.response_origin_version
  FROM secret_fixture_match_evidence e JOIN secret_fixture_manifests m ON m.manifest_id=e.manifest_id AND m.version=e.manifest_version
  JOIN secret_connection_scopes s ON s.scope_id=e.scope_id JOIN secret_credential_sets c ON c.credential_set_id=e.credential_set_id
  WHERE e.credential_set_id=? AND c.component_state='CONFIRMED' AND e.match_result='MATCH'
   AND e.comparator_id='LOGSSEY_PROTECTED_IDENTITY' AND e.comparator_version='1'
   AND s.enabled AND s.response_origin='TEST' AND s.revision=e.scope_revision
   AND m.approval_status='APPROVED' AND m.revoked_at IS NULL AND m.valid_from<=CURRENT_TIMESTAMP
   AND (m.valid_until IS NULL OR m.valid_until>CURRENT_TIMESTAMP)
   AND NOT EXISTS(SELECT 1 FROM secret_test_fixture_attestations a WHERE a.match_evidence_id=e.match_evidence_id)
   AND NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=c.credential_set_id)
   AND EXISTS(SELECT 1 FROM secret_fixture_manifest_identities i WHERE i.manifest_id=e.manifest_id AND i.manifest_version=e.manifest_version
    AND i.scope_id=e.scope_id AND i.scope_revision=e.scope_revision AND i.issuer=c.issuer AND i.credential_type=c.credential_type
    AND i.fingerprint_key_version=c.fingerprint_key_version AND i.protected_fingerprint=c.fingerprint)
  ORDER BY e.match_evidence_id DESC
  """,key);}
 private long scopeConnection(long scope){return jdbc.query("SELECT connection_id FROM secret_connection_scopes WHERE scope_id=?",(rs,n)->rs.getLong(1),scope).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));}
 private void requireKeyRead(SecretPrincipal actor,long key){boolean allowed=jdbc.queryForList("SELECT DISTINCT connection_id FROM secret_occurrences WHERE credential_set_id=?",key).stream()
  .anyMatch(o->access.hasConnectionRole(actor,number(o,"connection_id"),SecretRole.SECURITY));if(!allowed)throw new ApiException(ErrorCode.NOT_FOUND);}
 private String visibleFixtureStatus(SecretPrincipal actor,long key){
  var states=jdbc.queryForList("SELECT fs.fixture_status,s.connection_id FROM secret_test_fixture_status fs JOIN secret_connection_scopes s ON s.scope_id=fs.scope_id WHERE fs.credential_set_id=?",key).stream()
   .filter(r->access.hasConnectionRole(actor,number(r,"connection_id"),SecretRole.SECURITY)).map(r->(String)r.get("fixture_status")).toList();
  for(String status:List.of("CONFIRMED_REAL","POSSIBLE_REAL","VERIFIED_SYNTHETIC"))if(states.contains(status))return status;return "NOT_APPLICABLE";
 }
 private static Map<String,Object> attestation(Map<String,Object> r){Map<String,Object> item=new LinkedHashMap<>();
  String[][] names={{"attestationId","attestation_id"},{"scopeId","scope_id"},{"scopeRevision","scope_revision"},{"manifestId","manifest_id"},{"manifestVersion","manifest_version"},{"matchEvidenceId","match_evidence_id"},{"confirmationSource","confirmation_source"},{"status","status"}};
  for(var n:names)item.put(n[0],r.get(n[1]));item.put("confirmedAt",time(r,"confirmed_at"));return item;
 }
}
