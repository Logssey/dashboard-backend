package com.logssey.secretworker.evidence;

import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Operator-side registration boundary. Deliberately absent from HTTP controllers and AI inputs. */
public final class TrustedFixtureManifestRegistrar {
 private final JdbcTemplate jdbc;private final TransactionTemplate transaction;
 public TrustedFixtureManifestRegistrar(JdbcTemplate jdbc,PlatformTransactionManager manager){this.jdbc=jdbc;this.transaction=new TransactionTemplate(manager);}
 public record Identity(long scopeId,long scopeRevision,String issuer,String credentialType,String keyVersion,byte[] protectedFingerprint){
  public Identity {protectedFingerprint=protectedFingerprint.clone();if(scopeId<=0||scopeRevision<=0||protectedFingerprint.length!=32)throw new IllegalArgumentException("FIXTURE_IDENTITY_INVALID");}
  @Override public byte[] protectedFingerprint(){return protectedFingerprint.clone();}
  @Override public String toString(){return "FixtureIdentity[scopeId="+scopeId+"]";}
 }
 public long registerApproved(String protectedManifestRef,long approverUserId,OffsetDateTime validFrom,OffsetDateTime validUntil,boolean allowAutoAttestation,List<Identity> identities){
  if(protectedManifestRef==null||!protectedManifestRef.matches("FIXTURE:[A-Z][A-Z0-9_-]{0,79}")||approverUserId<=0||validFrom==null||identities==null||identities.isEmpty()||identities.size()>1000||validUntil!=null&&!validUntil.isAfter(validFrom))throw new IllegalArgumentException("FIXTURE_MANIFEST_INVALID");
  try {return Objects.requireNonNull(transaction.execute(ignored->{
   long id=jdbc.queryForObject("INSERT INTO secret_fixture_manifests(version,protected_manifest_ref,approval_status,valid_from,valid_until,allow_auto_attestation) VALUES(1,?,'DRAFT',?,?,?) RETURNING manifest_id",Long.class,protectedManifestRef,validFrom,validUntil,allowAutoAttestation);
   for(var identity:identities){byte[] protectedBytes=identity.protectedFingerprint();try{
    jdbc.update("""
     INSERT INTO secret_fixture_manifest_identities(manifest_id,manifest_version,scope_id,scope_revision,issuer,credential_type,fingerprint_key_version,protected_fingerprint)
     VALUES(?,1,?,?,?,?,?,?)
     """,id,identity.scopeId(),identity.scopeRevision(),identity.issuer(),identity.credentialType(),identity.keyVersion(),protectedBytes);
   }finally{Arrays.fill(protectedBytes,(byte)0);}}
   jdbc.update("UPDATE secret_fixture_manifests SET approval_status='APPROVED',approved_by_user_id=? WHERE manifest_id=? AND version=1",approverUserId,id);
   return id;
  }));}catch(org.springframework.dao.DataAccessException rejected){throw new IllegalStateException("FIXTURE_REGISTRATION_FAILED");}
 }
}
