package com.logssey.secretworker.validation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.sts.model.StsException;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/** A single in-memory attempt. Scheduling, deduplication, and persistence belong to the worker. */
@Component
public final class AwsCredentialValidator implements AwsValidationService {
    @FunctionalInterface
    interface StsCaller {
        void getCallerIdentity(AwsKeyMaterial key);
        default com.logssey.secret.permission.core.SecretProviderIdentity observeIdentity(AwsKeyMaterial key){getCallerIdentity(key);return null;}
    }

    private final boolean enabled;
    private final Clock clock;
    private final StsCaller sts;

    @Autowired
    public AwsCredentialValidator(@Value("${logssey.secret.validation.aws.enabled:false}") boolean enabled) {
        this(enabled, Clock.systemUTC(), new AwsStsCaller());
    }

    AwsCredentialValidator(boolean enabled, Clock clock, StsCaller sts) {
        this.enabled = enabled;
        this.clock = Objects.requireNonNull(clock);
        this.sts = Objects.requireNonNull(sts);
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public AwsValidationResult validate(AwsKeyMaterial key) {
        Instant evaluatedAt = clock.instant();
        if (!enabled) {
            return result(AwsValidationResult.Status.UNCHECKED, AwsValidationResult.Reason.DISABLED,
                    evaluatedAt, null);
        }
        if (key == null || !key.isComplete()) {
            AwsValidationResult.Reason reason = key != null && key.accessKeyId() != null
                    && key.accessKeyId().startsWith("ASIA") && key.secretAccessKey() != null
                    && !key.secretAccessKey().isBlank()
                    ? AwsValidationResult.Reason.MISSING_SESSION_TOKEN
                    : AwsValidationResult.Reason.INCOMPLETE_PAIR;
            return result(AwsValidationResult.Status.UNCHECKED, reason, evaluatedAt, null);
        }

        try {
            var identity=sts.observeIdentity(key);
            return new AwsValidationResult(AwsValidationResult.Status.VALID, AwsValidationResult.Reason.AUTHENTICATED,
                    evaluatedAt, clock.instant(),AwsValidationResult.METHOD,AwsValidationResult.VERSION,identity);
        } catch (StsException exception) {
            return classifySts(exception, evaluatedAt, clock.instant());
        } catch (RuntimeException exception) {
            // SDK client, network, configuration, and unexpected failures cannot prove invalidity.
            return result(AwsValidationResult.Status.UNKNOWN, AwsValidationResult.Reason.CLIENT_FAILURE,
                    evaluatedAt,
                    null);
        }
    }

    private static AwsValidationResult classifySts(StsException exception, Instant evaluatedAt, Instant checkedAt) {
        AwsErrorDetails details = exception.awsErrorDetails();
        String code = details == null ? null : details.errorCode();
        if ("InvalidClientTokenId".equals(code)) {
            return result(AwsValidationResult.Status.INVALID, AwsValidationResult.Reason.INVALID_ACCESS_KEY,
                    evaluatedAt, checkedAt);
        }
        if ("SignatureDoesNotMatch".equals(code)) {
            // A wrong secret is one cause, but proxy/signing/region problems can produce the same
            // code.
            return result(AwsValidationResult.Status.UNKNOWN, AwsValidationResult.Reason.SIGNATURE_AMBIGUOUS,
                    evaluatedAt, checkedAt);
        }
        if ("ExpiredToken".equals(code)) {
            return result(AwsValidationResult.Status.INVALID, AwsValidationResult.Reason.EXPIRED_SESSION,
                    evaluatedAt, checkedAt);
        }
        if ("Throttling".equals(code) || "ThrottlingException".equals(code)
                || "TooManyRequestsException".equals(code) || exception.statusCode() == 429) {
            return result(AwsValidationResult.Status.UNKNOWN, AwsValidationResult.Reason.RATE_LIMITED,
                    evaluatedAt, checkedAt);
        }
        if (exception.statusCode() == 401 || exception.statusCode() == 403 || exception.statusCode() == 404) {
            return result(AwsValidationResult.Status.UNKNOWN, AwsValidationResult.Reason.ACCESS_AMBIGUOUS,
                    evaluatedAt, checkedAt);
        }
        return result(AwsValidationResult.Status.UNKNOWN, AwsValidationResult.Reason.PROVIDER_UNAVAILABLE,
                evaluatedAt, checkedAt);
    }

    private static AwsValidationResult result(AwsValidationResult.Status status, AwsValidationResult.Reason reason,
                                              Instant evaluatedAt, Instant checkedAt) {
        return new AwsValidationResult(status, reason, evaluatedAt, checkedAt,
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
    }
}
