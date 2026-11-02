package com.logssey.secretworker.permission;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

class AwsPermissionObserverTest {
    @Test void aPolicyReadIsBoundToDiscoveredPrincipalNotTheCollectorsIdentity(){
        var iam=mock(IamClient.class,CALLS_REAL_METHODS);
        doReturn(GetUserResponse.builder().user(User.builder().arn("arn:aws:iam::123456789012:user/another-user").userId("AIDAOTHER").build()).build()).when(iam).getUser(any(GetUserRequest.class));
        var result=new AwsPermissionObserver().observeBound(Map.of("principal_ref","arn:aws:iam::123456789012:user/discovered","principal_id","AIDABOUND","principal_type","IAM_USER","account_ref","123456789012"),iam);
        assertThat(result.capabilities()).isEmpty();assertThat(result.reasonCodes()).containsExactly("CREDENTIAL_IDENTITY_MISMATCH");
        verify(iam,never()).listAttachedUserPolicies(any(ListAttachedUserPoliciesRequest.class));
    }
    @Test void aBoundAssumedRoleStillHasUnknownSessionAndOrganizationRestrictions(){
        var iam=mock(IamClient.class,CALLS_REAL_METHODS);
        doReturn(GetRoleResponse.builder().role(Role.builder().roleId("AROABOUND").arn("arn:aws:iam::123456789012:role/BoundRole").build()).build()).when(iam).getRole(any(GetRoleRequest.class));
        doReturn(ListAttachedRolePoliciesResponse.builder().attachedPolicies(AttachedPolicy.builder().policyArn("arn:aws:iam::123456789012:policy/BoundPolicy").build()).isTruncated(false).build()).when(iam).listAttachedRolePolicies(any(ListAttachedRolePoliciesRequest.class));
        doReturn(ListRolePoliciesResponse.builder().policyNames(List.of()).isTruncated(false).build()).when(iam).listRolePolicies(any(ListRolePoliciesRequest.class));
        doReturn(GetPolicyResponse.builder().policy(Policy.builder().defaultVersionId("v1").build()).build()).when(iam).getPolicy(any(GetPolicyRequest.class));
        doReturn(GetPolicyVersionResponse.builder().policyVersion(PolicyVersion.builder().document("{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"iam:*\",\"Resource\":\"*\"}}").build()).build()).when(iam).getPolicyVersion(any(GetPolicyVersionRequest.class));
        var result=new AwsPermissionObserver().observeBound(Map.of("principal_ref","arn:aws:sts::123456789012:assumed-role/BoundRole/session","principal_id","AROABOUND:session","principal_type","ASSUMED_ROLE","account_ref","123456789012"),iam);
        assertThat(result.status()).isEqualTo("PARTIAL");assertThat(result.capabilities()).containsExactly("IDENTITY_ADMINISTRATION");assertThat(result.reasonCodes()).contains("SESSION_POLICY_UNOBSERVED","ORGANIZATION_LIMITS_UNOBSERVED");
        verify(iam).getRole(argThat((GetRoleRequest request)->request.roleName().equals("BoundRole")));
    }
}
