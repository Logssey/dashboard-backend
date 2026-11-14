package com.logssey.secretworker.progress;

import static org.assertj.core.api.Assertions.*;
import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import software.amazon.awssdk.services.sts.model.StsException;

class AwsScanObservationTest {
    @Test void usesActualSdkStatusAndKeepsUnavailableStatusNull() {
        var statuses = new ArrayList<Integer>();
        ScanExecutionObserver observer = (stage, operation, outcome, status, reason, count, total, duration) -> {
            if (outcome != ScanExecutionObserver.Outcome.STARTED) statuses.add(status);
        };
        var response = GetCallerIdentityResponse.builder().account("111122223333")
                .sdkHttpResponse(SdkHttpResponse.builder().statusCode(200).build()).build();
        AwsScanObservation.call(observer, ScanExecutionObserver.Operation.AWS_GET_CALLER_IDENTITY, () -> response);
        AwsScanObservation.call(observer, ScanExecutionObserver.Operation.AWS_GET_CALLER_IDENTITY,
                () -> GetCallerIdentityResponse.builder().build());
        assertThat(statuses).containsExactly(200, null);
    }

    @Test void providerExceptionMessageNeverEntersObservation() {
        var facts = new ArrayList<String>();
        ScanExecutionObserver observer = (stage, operation, outcome, status, reason, count, total, duration) ->
                facts.add(operation + " " + outcome + " " + status + " " + reason);
        String raw = "private-arn-credential-provider-message";
        assertThatThrownBy(() -> AwsScanObservation.call(observer, ScanExecutionObserver.Operation.AWS_LIST_USERS,
                () -> { throw StsException.builder().statusCode(403).message(raw).build(); }))
                .isInstanceOf(StsException.class);
        assertThat(facts.toString()).contains("FAILED 403 OPERATION_FAILED").doesNotContain(raw);
    }
}
