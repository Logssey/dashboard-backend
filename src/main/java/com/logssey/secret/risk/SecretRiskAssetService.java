package com.logssey.secret.risk;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.*;
import com.logssey.secret.risk.core.SecretRiskAssessmentStore;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The inventory picker is global-security only; a linked asset is context, not permission proof. */
@Service
public class SecretRiskAssetService {
  private final JdbcTemplate jdbc;
  private final SecretAccessService access;

  public SecretRiskAssetService(JdbcTemplate jdbc, SecretAccessService access) {
    this.jdbc = jdbc;
    this.access = access;
  }

  @Transactional(readOnly = true)
  public Map<String, Object> list(String login, long occurrence, int page, int size) {
    if (page < 0 || page > 10000 || size < 1 || size > 100) throw new ApiException(ErrorCode.INVALID_INPUT);
    var actor = access.requirePrincipal(login);
    access.requireOccurrenceRead(actor, occurrence);
    var o = new SecretRiskAssessmentStore(jdbc).location(occurrence, false);
    boolean global = access.hasGlobalRole(actor, SecretRole.SECURITY);
    String issuer = Objects.toString(o.get("issuer"), "UNKNOWN");
    boolean supported = Set.of("AWS", "GITHUB", "KUBERNETES").contains(issuer)
        && !"METADATA_ONLY".equals(o.get("component_state"));
    List<Map<String, Object>> rows;
    long total;
    if (global && supported) {
      rows = jdbc.queryForList(
          "SELECT asset_id,name,provider,asset_type,environment FROM assets WHERE provider=?"
              + " ORDER BY asset_id LIMIT ? OFFSET ?", issuer, size, Math.multiplyExact(page, size));
      total = jdbc.queryForObject("SELECT count(*) FROM assets WHERE provider=?", Long.class, issuer);
    } else if (o.get("asset_id") != null && page == 0) {
      rows = jdbc.queryForList("SELECT asset_id,name,provider,asset_type,environment FROM assets WHERE asset_id=?", o.get("asset_id"));
      total = rows.size();
    } else {
      rows = List.of();
      total = o.get("asset_id") == null ? 0 : 1;
    }
    return Map.of("occurrenceId", occurrence, "evidenceRevision", o.get("risk_evidence_revision"),
        "items", rows.stream().map(SecretRiskAnalysisContext::safeAsset).toList(),
        "total", total, "page", page, "size", size,
        "capabilities", Map.of("canLinkAsset", global && supported),
        "limitations", List.of("MANUAL_ASSET_LINK_NOT_PERMISSION_PROOF"));
  }
}
