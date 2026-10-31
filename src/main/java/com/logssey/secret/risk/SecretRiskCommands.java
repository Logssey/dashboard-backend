package com.logssey.secret.risk;

import com.logssey.common.error.*;
import com.logssey.secret.access.SecretPrincipal;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

@Component
public class SecretRiskCommands {
  final JdbcTemplate jdbc;
  final TransactionTemplate tx;
  final JsonMapper json = JsonMapper.builder().findAndAddModules().build();

  public SecretRiskCommands(JdbcTemplate jdbc, PlatformTransactionManager manager) {
    this.jdbc = jdbc;
    this.tx = new TransactionTemplate(manager);
  }

  public Map<String, Object> execute(
      SecretPrincipal actor,
      String kind,
      String key,
      Object safe,
      Runnable authorize,
      Supplier<Map<String, Object>> mutation) {
    if (key == null || !key.matches("[A-Za-z0-9._:-]{1,120}")) throw SecretRiskFacts.invalid();
    String keyHash = HexFormat.of().formatHex(digest(key));
    byte[] request = digest(json.writeValueAsString(safe));
    return tx.execute(
        status -> {
          jdbc.queryForObject(
              "SELECT pg_advisory_xact_lock(?)",
              Object.class,
              ByteBuffer.wrap(digest(actor.userId() + ":" + kind + ":" + keyHash)).getLong());
          authorize.run();
          var previous =
              jdbc.queryForList(
                  "SELECT safe_request_digest,safe_result::text AS result FROM"
                      + " secret_command_idempotency WHERE actor_user_id=? AND command_kind=? AND"
                      + " idempotency_key=?",
                  actor.userId(),
                  kind,
                  keyHash);
          if (!previous.isEmpty()) {
            if (!MessageDigest.isEqual(
                request, (byte[]) previous.getFirst().get("safe_request_digest")))
              throw new ApiException(ErrorCode.CONFLICT);
            return read((String) previous.getFirst().get("result"));
          }
          var result = mutation.get();
          long command =
              jdbc.queryForObject(
                  "INSERT INTO"
                      + " secret_command_idempotency(actor_user_id,command_kind,idempotency_key,safe_request_digest,safe_result)"
                      + " VALUES(?,?,?,?,?::jsonb) RETURNING command_id",
                  Long.class,
                  actor.userId(),
                  kind,
                  keyHash,
                  request,
                  json.writeValueAsString(result));
          jdbc.update(
              "INSERT INTO"
                  + " secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,command_id,safe_changes)"
                  + " VALUES(?,?,'OCCURRENCE',?,?,?,?::jsonb)",
              kind,
              actor.userId(),
              ((Number) result.get("occurrenceId")).longValue(),
              ((Number) result.get("evidenceRevision")).longValue(),
              command,
              json.writeValueAsString(Map.of("reasonCode", kind)));
          return result;
        });
  }

  @SuppressWarnings("unchecked")
  Map<String, Object> read(String value) {
    Map<String, Object> result = json.readValue(value, Map.class);
    result.replaceAll((k, v) -> v instanceof Number n ? n.longValue() : v);
    return result;
  }

  public static byte[] digest(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA256_UNAVAILABLE");
    }
  }
}
