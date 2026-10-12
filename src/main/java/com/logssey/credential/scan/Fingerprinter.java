package com.logssey.credential.scan;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 키 원문 대신 저장하는 지문 (ADR-D009).
 * 서버 비밀값을 섞은 HMAC-SHA256이라, 비밀값을 모르면 대입해서 원문을 맞혀 볼 수 없다.
 * 비밀값을 바꾸면 기존 지문과 비교할 수 없으므로 앞에 버전(v1)을 붙인다 (ERD 초안 1.1).
 */
public final class Fingerprinter {

    static final String PREFIX = "hmac-sha256:v1:";

    private final byte[] key;

    public Fingerprinter(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("fingerprint secret must not be blank");
        }
        this.key = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String fingerprint(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return PREFIX + HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }

    @Override
    public String toString() {
        return "Fingerprinter[key=****]";
    }
}
