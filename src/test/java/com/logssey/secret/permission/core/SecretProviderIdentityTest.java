package com.logssey.secret.permission.core;
import static org.assertj.core.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
class SecretProviderIdentityTest {
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
