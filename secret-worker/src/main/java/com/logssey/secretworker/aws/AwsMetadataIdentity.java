package com.logssey.secretworker.aws;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC keeps even the non-secret IAM key identifier out of result tables. */
public final class AwsMetadataIdentity {
    private final byte[] key;
    private final String version;

    public static AwsMetadataIdentity fromBase64(String encoded, String version) {
        try {
            return new AwsMetadataIdentity(Base64.getDecoder().decode(encoded), version);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("AWS_METADATA_IDENTITY_KEY_INVALID");
        }
    }

    public AwsMetadataIdentity(byte[] key, String version) {
        if (key == null || key.length < 32 || version == null
                || !version.matches("[A-Za-z0-9._-]{1,40}")) {
            throw new IllegalArgumentException("AWS_METADATA_IDENTITY_KEY_INVALID");
        }
        this.key = key.clone();
        this.version = version;
    }

    public String reference(String accountId, String accessKeyId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(accountId.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) 0);
            mac.update(accessKeyId.getBytes(StandardCharsets.US_ASCII));
            return "hmac:" + version + ":" + HexFormat.of().formatHex(mac.doFinal());
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("AWS_METADATA_IDENTITY_UNAVAILABLE");
        }
    }
}
