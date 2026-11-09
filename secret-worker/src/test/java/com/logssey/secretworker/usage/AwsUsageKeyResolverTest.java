package com.logssey.secretworker.usage;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.aws.AwsMetadataIdentity;
import java.util.*;
import org.junit.jupiter.api.Test;
class AwsUsageKeyResolverTest {
    final SecretFindingNormalizer normalizer=new SecretFindingNormalizer(new byte[32],"test");
    final AwsMetadataIdentity metadata=new AwsMetadataIdentity(new byte[32],"test");
    final AwsUsageGateway gateway=mock(AwsUsageGateway.class);
    final String key="AKIA"+"A".repeat(16),other="AKIA"+"B".repeat(16),account="123456789012",arn="arn:aws:iam::123456789012:user/fixture";
    Map<String,Object> source(){return new HashMap<>(Map.of("component_state","CONFIRMED","credential_type","AWS_ACCESS_KEY_PAIR","fingerprint_key_version","test","aws_key_id_fingerprint",normalizer.keyIdentifierFingerprint(key),"principal_type","IAM_USER","principal_ref",arn,"principal_id","fixture-id"));}
    @Test void fullCredentialFingerprintIsNeverUsedAsAnIdFingerprint(){var c=source();c.remove("aws_key_id_fingerprint");c.put("fingerprint",new byte[32]);assertThatThrownBy(()->new AwsUsageKeyResolver(normalizer,metadata).resolve(c,account,gateway,()->{})).hasMessage("KEY_IDENTIFIER_UNAVAILABLE");verifyNoInteractions(gateway);}
    @Test void twoKeysOfTheSamePrincipalRemainDistinct(){when(gateway.principal("fixture")).thenReturn(new AwsUsageGateway.Principal(arn,"fixture-id"));when(gateway.accessKeyIds("fixture")).thenReturn(List.of(other,key));assertThat(new AwsUsageKeyResolver(normalizer,metadata).resolve(source(),account,gateway,()->{})).isEqualTo(key);}
    @Test void identityMismatchStopsBeforeListingKeys(){when(gateway.principal("fixture")).thenReturn(new AwsUsageGateway.Principal(arn,"other-principal"));assertThatThrownBy(()->new AwsUsageKeyResolver(normalizer,metadata).resolve(source(),account,gateway,()->{})).hasMessage("IDENTITY_BINDING_UNRESOLVED");verify(gateway,never()).accessKeyIds(any());}
    @Test void metadataUsesItsOwnAccountBoundDigest(){when(gateway.userNames()).thenReturn(List.of("fixture"));when(gateway.accessKeyIds("fixture")).thenReturn(List.of(other,key));var c=Map.<String,Object>of("component_state","METADATA_ONLY","external_key_ref",metadata.reference(account,key));assertThat(new AwsUsageKeyResolver(normalizer,metadata).resolve(c,account,gateway,()->{})).isEqualTo(key);}
}
