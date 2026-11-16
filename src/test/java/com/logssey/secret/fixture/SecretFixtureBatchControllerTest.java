package com.logssey.secret.fixture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import com.logssey.common.error.*;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class SecretFixtureBatchControllerTest {
    @Test void keepsPerItemAuthorizationFailuresAndReturnsCommittedSuccesses() {
        var service=mock(SecretFixtureService.class);
        var first=new SecretFixtureService.Attest(1L,1L,1L,1L,1L,"first");
        var second=new SecretFixtureService.Attest(2L,1L,1L,1L,2L,"second");
        when(service.attest("security",10L,first)).thenReturn(Map.of("attestationId",100L));
        when(service.attest("security",11L,second)).thenThrow(new ApiException(ErrorCode.FORBIDDEN));
        var result=new SecretFixtureBatchController(service).attest(new SecretFixtureBatchController.Batch(List.of(
                new SecretFixtureBatchController.Item(10L,first),new SecretFixtureBatchController.Item(11L,second))),
                new UsernamePasswordAuthenticationToken("security","unused"));
        assertThat(result).containsEntry("succeededCount",1L).containsEntry("failedCount",1L);
        verify(service).attest("security",10L,first);verify(service).attest("security",11L,second);
    }
}
