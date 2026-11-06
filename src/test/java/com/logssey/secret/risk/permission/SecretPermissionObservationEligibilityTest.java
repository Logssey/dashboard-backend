package com.logssey.secret.risk.permission;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.logssey.secret.access.*;
import com.logssey.secret.permission.core.SecretPermissionContext;
import java.time.OffsetDateTime;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

class SecretPermissionObservationEligibilityTest {
  @Test void candidateSignalRequiresCollectorReadAccessAndUnchangedApproval() {
    var jdbc = mock(JdbcTemplate.class); var access = mock(SecretAccessService.class);
    var actor = new SecretPrincipal(1); var now = OffsetDateTime.now();
    var source = new HashMap<String,Object>(Map.of("connection_id",1L,"scope_id",1L,"issuer","AWS",
        "connection_status","ACTIVE","scope_enabled",true,"identity_id",7L,"account_ref","123456789012"));
    var collector = new HashMap<String,Object>(Map.of("provider","AWS","status","ACTIVE","enabled",true,
        "auth_ref","protected-reference","scope_version",2L,"scope_id",9L,"revision",3L,
        "approved_ref","aws://123456789012/global/iam/access-keys","content_type","IAM_ACCESS_KEY_METADATA"));
    var baseline = Map.of("sourceContextVersion",SecretPermissionContext.sourceVersion(source),
        "collectorScopeId",9L,"collectorScopeVersion",2L,"collectorScopeRevision",3L,
        "collectorAuthRef","protected-reference","collectorApprovedRef","aws://123456789012/global/iam/access-keys");
    var observation = new HashMap<String,Object>(Map.of("collector_connection_id",2L,"identity_id",7L,
        "status","PARTIAL","observed_at",now.minusMinutes(1),"expires_at",now.plusHours(1),
        "baseline",new JsonMapper().writeValueAsString(baseline)));
    when(jdbc.queryForList(anyString(),eq(2L),eq(9L))).thenReturn(List.of(collector));
    when(access.canReadConnectionFacts(actor,2L)).thenReturn(false);
    assertThat(SecretPermissionObservationEligibility.current(jdbc,access,actor,source,observation,now)).isFalse();
    verifyNoInteractions(jdbc);
    when(access.canReadConnectionFacts(actor,2L)).thenReturn(true);
    assertThat(SecretPermissionObservationEligibility.current(jdbc,access,actor,source,observation,now)).isTrue();
    for (var change : List.of(Map.entry("auth_ref","rotated"),Map.entry("status","DISABLED"),
        Map.entry("scope_version",4L),Map.entry("revision",4L),Map.entry("enabled",false),
        Map.entry("approved_ref","aws://000000000000/global/iam/access-keys"))) {
      Object original = collector.put(change.getKey(),change.getValue());
      assertThat(SecretPermissionObservationEligibility.current(jdbc,access,actor,source,observation,now)).as(change.getKey()).isFalse();
      collector.put(change.getKey(),original);
    }
    observation.put("expires_at",now);
    assertThat(SecretPermissionObservationEligibility.current(jdbc,access,actor,source,observation,now)).isFalse();
  }
}
