package com.logssey.secretworker.progress;

import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;
import java.util.function.Supplier;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkResponse;

/** Records the SDK response status when present, without serializing requests or responses. */
public final class AwsScanObservation {
    private AwsScanObservation() {}

    public static <T extends SdkResponse> T call(ScanExecutionObserver observer, Operation operation, Supplier<T> call) {
        observer.record(Stage.COLLECTION, operation, Outcome.STARTED, null, null, null, null, null);
        long started = System.nanoTime();
        T response;
        try {
            response = call.get();
        } catch (AwsServiceException failure) {
            observer.record(Stage.COLLECTION, operation, Outcome.FAILED,
                    validStatus(failure.statusCode()),
                    failure.statusCode() == 429 || failure.statusCode() == 503 ? "RATE_LIMITED" : "OPERATION_FAILED",
                    null, null, ScanExecutionObserver.elapsed(started));
            throw failure;
        } catch (RuntimeException failure) {
            observer.record(Stage.COLLECTION, operation, Outcome.FAILED, null,
                    "NETWORK_ERROR", null, null, ScanExecutionObserver.elapsed(started));
            throw failure;
        }
        Integer status = response.sdkHttpResponse() == null ? null : validStatus(response.sdkHttpResponse().statusCode());
        observer.record(Stage.COLLECTION, operation, Outcome.COMPLETED, status, null,
                null, null, ScanExecutionObserver.elapsed(started));
        return response;
    }

    public static Integer validStatus(int status) { return status >= 100 && status <= 599 ? status : null; }
}
