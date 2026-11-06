package com.logssey.secret.permission.core;
import static org.assertj.core.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
class SecretProviderIdentityTest {
    private static final String NOTION_BOT = "1a111111-2222-3333-4444-555555555555";
    private static final String NOTION_WORKSPACE = "6b666666-7777-8888-9999-aaaaaaaaaaaa";

    @Test void notionIdentityKeepsOnlyVersionedProviderMetadata() {
        var identity = SecretProviderIdentity.notion(NOTION_BOT.toUpperCase(Locale.ROOT),
                NOTION_WORKSPACE.toUpperCase(Locale.ROOT), "workspace");
        assertThat(identity.provider()).isEqualTo("NOTION");
        assertThat(identity.principalType()).isEqualTo("NOTION_BOT");
        assertThat(identity.principalId()).isEqualTo(NOTION_BOT);
        assertThat(identity.principalRef()).isEqualTo("notion-bot:" + NOTION_BOT);
        assertThat(identity.accountRef()).isNull();
        assertThat(identity.claims()).containsExactlyInAnyOrderEntriesOf(Map.of(
                "schemaVersion", 1, "workspaceRef", NOTION_WORKSPACE, "ownerType", "workspace"));
        assertThat(SecretProviderIdentity.notion(NOTION_BOT, null, null).claims())
                .containsExactlyEntriesOf(Map.of("schemaVersion", 1));
        assertThatThrownBy(() -> identity.claims().put("name", "not-allowed"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test void notionIdentityRejectsUnboundIdsAndUnapprovedClaims() {
        assertThatThrownBy(() -> SecretProviderIdentity.notion("not-a-uuid", null, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SecretProviderIdentity.notion(NOTION_BOT, "not-a-uuid", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SecretProviderIdentity.notion(NOTION_BOT, null, "admin"))
                .isInstanceOf(IllegalArgumentException.class);
        for (var claims : List.of(Map.<String, Object>of(),
                Map.<String, Object>of("schemaVersion", 2),
                Map.<String, Object>of("schemaVersion", 1, "token", "SENTINEL_RAW_DO_NOT_STORE"))) {
            assertThatThrownBy(() -> new SecretProviderIdentity("NOTION", "NOTION_BOT", null,
                    "notion-bot:" + NOTION_BOT, NOTION_BOT, claims))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new SecretProviderIdentity("NOTION", "NOTION_BOT", "123456789012",
                "notion-bot:" + NOTION_BOT, NOTION_BOT, Map.of("schemaVersion", 1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SecretProviderIdentity("NOTION", "NOTION_BOT", null,
                "notion-bot:" + NOTION_WORKSPACE, NOTION_BOT, Map.of("schemaVersion", 1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void rawUnknownHeaderValuesNeverPersistAsClaims(){
        var identity=SecretProviderIdentity.github(123,true,"repo, admin:org, synthetic_sensitive_value_not_a_scope");
        assertThat(identity.claims()).containsEntry("scopes",List.of("admin:org","repo")).containsEntry("scopesComplete",false);
        assertThat(identity.toString()).doesNotContain("synthetic_sensitive_value");
        var fine=SecretProviderIdentity.github(123,false,null);assertThat(fine.claims()).containsEntry("scopes",List.of()).containsEntry("scopesComplete",false);
    }
    @Test void awsAccountAndPrincipalMustAgreeAndSourceBaselineExcludesOnlyManualSupplement(){
        assertThatThrownBy(()->SecretProviderIdentity.aws("123456789012","arn:aws:iam::999999999999:user/example","AIDABOUND")).isInstanceOf(IllegalArgumentException.class);
        var before=new HashMap<String,Object>(Map.of("occurrence_id",1,"credential_revision",1,"scope_revision",1,"identity_id",2,"risk_evidence_revision",0));
        var supplement=new HashMap<>(before);supplement.put("risk_evidence_revision",3);supplement.put("asset_id",99);
        assertThat(SecretPermissionContext.sourceVersion(before)).isEqualTo(SecretPermissionContext.sourceVersion(supplement));
        assertThat(SecretPermissionContext.version(before)).isNotEqualTo(SecretPermissionContext.version(supplement));
        supplement.put("scope_revision",2);assertThat(SecretPermissionContext.sourceVersion(before)).isNotEqualTo(SecretPermissionContext.sourceVersion(supplement));
    }
}
