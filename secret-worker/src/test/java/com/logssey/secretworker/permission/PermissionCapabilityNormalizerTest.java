package com.logssey.secretworker.permission;
import static org.assertj.core.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class PermissionCapabilityNormalizerTest {
    @Test void wildcardPolicyIsPotentialCapabilityNotConfirmedEffectiveAdmin(){
        String policy="{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"},{\"Effect\":\"Deny\",\"Action\":\"iam:*\",\"Resource\":\"*\"}]}";
        var result=new PermissionCapabilityNormalizer().aws(List.of(policy),true,false);
        assertThat(result.status()).isEqualTo("PARTIAL");assertThat(result.capabilities()).contains("IDENTITY_ADMINISTRATION");
        assertThat(result.coverage()).containsEntry("restrictionCoverage","UNKNOWN");
        assertThat(result.reasonCodes()).contains("EFFECTIVE_PERMISSION_NOT_PROVEN","ORGANIZATION_LIMITS_UNOBSERVED");
        assertThat(result.facts().toString()).doesNotContain("\"Effect\"","\"Resource\"","\"Action\"");
    }
    @Test void partialPolicyPaginationAndUnknownSessionLimitsNeverBecomeComplete(){
        var result=new PermissionCapabilityNormalizer().aws(List.of("{\"Statement\":{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"*\"}}"),false,true);
        assertThat(result.capabilities()).containsExactly("RESOURCE_READ");assertThat(result.coverage()).containsEntry("permissionCoverage","PARTIAL").containsEntry("restrictionCoverage","UNKNOWN");
        assertThat(result.reasonCodes()).contains("POLICY_COLLECTION_PARTIAL","SESSION_POLICY_UNOBSERVED");
    }
    @Test void githubOwnerAndTokenScopeDoNotProveRepositoryAuthorization(){
        var result=new PermissionCapabilityNormalizer().github(Map.of("tokenKind","CLASSIC","scopes",List.of("admin:org","repo"),"scopesComplete",true));
        assertThat(result.status()).isEqualTo("PARTIAL");assertThat(result.capabilities()).contains("IDENTITY_ADMINISTRATION","DATA_WRITE");
        assertThat(result.coverage()).containsEntry("targetCoverage","UNKNOWN").containsEntry("restrictionCoverage","UNKNOWN");
        assertThat(result.reasonCodes()).contains("TOKEN_OWNER_NOT_EFFECTIVE_PERMISSION","REPOSITORY_AUTHORIZATION_UNOBSERVED");
        var fine=new PermissionCapabilityNormalizer().github(Map.of("tokenKind","FINE_GRAINED","scopes",List.of(),"scopesComplete",false));
        assertThat(fine.capabilities()).isEmpty();assertThat(fine.reasonCodes()).contains("TOKEN_PERMISSIONS_UNAVAILABLE");
    }
}
