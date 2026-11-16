package com.logssey.secret.connection.core;

import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Secret-bearing material is never a response DTO and always has a redacted string form. */
public final class GitHubSourceCredential {
    private static final byte[] RSA_ALGORITHM = {
        0x30,
        0x0d,
        0x06,
        0x09,
        0x2a,
        (byte) 0x86,
        0x48,
        (byte) 0x86,
        (byte) 0xf7,
        0x0d,
        0x01,
        0x01,
        0x01,
        0x05,
        0x00
    };
    private final long appId;
    private final long installationId;
    private final String pem;
    private final PrivateKey key;

    public GitHubSourceCredential(long appId, long installationId, String pem) {
        if (appId <= 0 || installationId <= 0 || pem == null || pem.length() > 32_768)
            throw invalid();
        this.appId = appId;
        this.installationId = installationId;
        this.pem = pem.strip();
        this.key = parse(this.pem);
    }

    public long appId() {
        return appId;
    }

    public long installationId() {
        return installationId;
    }

    public PrivateKey privateKey() {
        return key;
    }

    public String secretPayload() {
        var value = new java.util.TreeMap<String, Object>();
        value.put("appId", appId);
        value.put("installationId", installationId);
        value.put("privateKey", pem);
        return new JsonMapper().writeValueAsString(value);
    }

    public static GitHubSourceCredential fromPayload(String payload) {
        try {
            if (payload == null || payload.length() > 40_000) throw invalid();
            var value = new JsonMapper().readTree(payload);
            return new GitHubSourceCredential(
                    value.path("appId").asLong(0),
                    value.path("installationId").asLong(0),
                    value.path("privateKey").asText(""));
        } catch (RuntimeException ignored) {
            throw invalid();
        }
    }

    public static GitHubSourceCredential fromFile(long app, long installation, Path path) {
        byte[] bytes = null;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(32_769);
            if (bytes.length > 32_768) throw invalid();
            return new GitHubSourceCredential(
                    app, installation, new String(bytes, StandardCharsets.US_ASCII));
        } catch (Exception ignored) {
            throw invalid();
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    private static PrivateKey parse(String pem) {
        byte[] decoded = null;
        byte[] encoded = null;
        try {
            boolean pkcs1 =
                    pem.startsWith(marker("BEGIN", "RSA PRIVATE KEY"))
                            && pem.endsWith(marker("END", "RSA PRIVATE KEY"));
            boolean pkcs8 =
                    pem.startsWith(marker("BEGIN", "PRIVATE KEY"))
                            && pem.endsWith(marker("END", "PRIVATE KEY"));
            if (pkcs1 == pkcs8) throw invalid();
            String type = pkcs1 ? "RSA PRIVATE KEY" : "PRIVATE KEY";
            String header = marker("BEGIN", type);
            String footer = marker("END", type);
            decoded =
                    Base64.getDecoder()
                            .decode(
                                    pem.substring(header.length(), pem.length() - footer.length())
                                            .replaceAll("\\s", ""));
            if (pkcs1) {
                byte[] octet = der(0x04, decoded);
                byte[] body = new byte[3 + RSA_ALGORITHM.length + octet.length];
                body[0] = 0x02;
                body[1] = 0x01;
                body[2] = 0x00;
                System.arraycopy(RSA_ALGORITHM, 0, body, 3, RSA_ALGORITHM.length);
                System.arraycopy(octet, 0, body, 3 + RSA_ALGORITHM.length, octet.length);
                encoded = der(0x30, body);
                Arrays.fill(body, (byte) 0);
                Arrays.fill(octet, (byte) 0);
            } else encoded = decoded;
            PrivateKey key =
                    KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
            if (!(key instanceof RSAPrivateKey rsa) || rsa.getModulus().bitLength() < 2048)
                throw invalid();
            return key;
        } catch (Exception ignored) {
            throw invalid();
        } finally {
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
        }
    }

    private static String marker(String boundary, String type) {
        return "-----" + boundary + " " + type + "-----";
    }

    private static byte[] der(int tag, byte[] value) {
        int n = value.length;
        int lengths = n < 128 ? 1 : n < 256 ? 2 : 3;
        byte[] result = new byte[1 + lengths + n];
        result[0] = (byte) tag;
        if (lengths == 1) result[1] = (byte) n;
        else {
            result[1] = (byte) (0x80 | lengths - 1);
            for (int i = 2; i <= lengths; i++) result[i] = (byte) (n >> (8 * (lengths - i)));
        }
        System.arraycopy(value, 0, result, 1 + lengths, n);
        return result;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("GITHUB_SOURCE_CREDENTIAL_INVALID");
    }

    @Override
    public String toString() {
        return "GitHubSourceCredential[redacted]";
    }
}
