package com.logssey.secret.aws;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.core.SdkSystemSetting;
import software.amazon.awssdk.utils.SdkAutoCloseable;
import java.util.function.Predicate;

/** Explicit source identity. Discovered credentials never use this provider. */
public final class SecretAwsSourceCredentials implements AwsCredentialsProvider, SdkAutoCloseable {
    public static final String WORKLOAD_REF = "aws-workload:default";
    private final String authRef;
    private final AwsCredentialsProvider delegate;

    SecretAwsSourceCredentials(String authRef, AwsCredentialsProvider delegate) {
        this.authRef = authRef;
        this.delegate = java.util.Objects.requireNonNull(delegate);
    }

    public static SecretAwsSourceCredentials fromConfiguration(String mode, String profile) {
        return switch (mode == null ? "" : mode) {
            case "PROFILE" -> profile(profile);
            case "WORKLOAD" -> {
                if (profile != null && !profile.isBlank())
                    throw new IllegalArgumentException("AWS_WORKLOAD_PROFILE_FORBIDDEN");
                yield workload();
            }
            default -> throw new IllegalArgumentException("AWS_CREDENTIALS_MODE_INVALID");
        };
    }

    public static SecretAwsSourceCredentials profile(String name) {
        if (name == null || !name.matches("[A-Za-z0-9._-]{1,100}"))
            throw new IllegalArgumentException("AWS_PROFILE_REQUIRED");
        // A failed explicit profile must never fall back to another identity.
        return new SecretAwsSourceCredentials("aws-profile:" + name, ProfileCredentialsProvider.create(name));
    }

    public static SecretAwsSourceCredentials workload() {
        // Select one identity source before resolving it. Broken explicit IRSA/ECS
        // settings must not fall through to a more privileged node/instance role.
        AwsCredentialsProvider provider = switch (workloadKind(SecretAwsSourceCredentials::isConfigured)) {
            case WEB_IDENTITY -> WebIdentityTokenFileCredentialsProvider.create();
            case CONTAINER -> ContainerCredentialsProvider.builder().build();
            case INSTANCE -> InstanceProfileCredentialsProvider.builder().build();
        };
        return new SecretAwsSourceCredentials(WORKLOAD_REF, provider);
    }

    enum WorkloadKind { WEB_IDENTITY, CONTAINER, INSTANCE }

    static WorkloadKind workloadKind(Predicate<SdkSystemSetting> configured) {
        if (configured.test(SdkSystemSetting.AWS_WEB_IDENTITY_TOKEN_FILE)
                || configured.test(SdkSystemSetting.AWS_ROLE_ARN)
                || configured.test(SdkSystemSetting.AWS_ROLE_SESSION_NAME)) return WorkloadKind.WEB_IDENTITY;
        if (configured.test(SdkSystemSetting.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
                || configured.test(SdkSystemSetting.AWS_CONTAINER_CREDENTIALS_FULL_URI)
                || configured.test(SdkSystemSetting.AWS_CONTAINER_AUTHORIZATION_TOKEN)
                || configured.test(SdkSystemSetting.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)) return WorkloadKind.CONTAINER;
        return WorkloadKind.INSTANCE;
    }

    private static boolean isConfigured(SdkSystemSetting setting) {
        // Presence includes an empty/malformed explicit value: that must fail its
        // selected SDK provider rather than enabling fallback to the node role.
        return setting.property() != null && System.getProperty(setting.property()) != null
                || setting.environmentVariable() != null && System.getenv(setting.environmentVariable()) != null;
    }

    public String authRef() { return authRef; }

    public static boolean isReference(String value) {
        return WORKLOAD_REF.equals(value)
                || value != null && value.matches("aws-profile:[A-Za-z0-9._-]{1,100}");
    }

    @Override public AwsCredentials resolveCredentials() { return delegate.resolveCredentials(); }

    @Override public void close() {
        if (delegate instanceof SdkAutoCloseable closeable) closeable.close();
    }
}
