package com.logssey.secret.connection;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Loads GitHub-generated PKCS#1 or PKCS#8 PEM without returning source bytes in errors. */
final class GitHubPrivateKeyReader {
    private static final byte[] RSA_ALGORITHM = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };

    private GitHubPrivateKeyReader() { }

    static PrivateKey read(Path path) {
        byte[] pemBytes = null;
        byte[] decoded = null;
        byte[] encoded = null;
        try {
            try (var stream = Files.newInputStream(path)) {
                pemBytes = stream.readNBytes(32_769);
            }
            if (pemBytes.length > 32_768) throw new IllegalArgumentException("KEY_TOO_LARGE");
            String pem = new String(pemBytes, java.nio.charset.StandardCharsets.US_ASCII);
            boolean pkcs1 = pem.contains("-----BEGIN RSA PRIVATE KEY-----")
                    && pem.contains("-----END RSA PRIVATE KEY-----");
            boolean pkcs8 = pem.contains("-----BEGIN PRIVATE KEY-----")
                    && pem.contains("-----END PRIVATE KEY-----");
            if (pkcs1 == pkcs8) throw new IllegalArgumentException("KEY_FORMAT");
            String header = pkcs1 ? "-----BEGIN RSA PRIVATE KEY-----" : "-----BEGIN PRIVATE KEY-----";
            String footer = pkcs1 ? "-----END RSA PRIVATE KEY-----" : "-----END PRIVATE KEY-----";
            decoded = Base64.getDecoder().decode(pem.substring(
                    pem.indexOf(header) + header.length(), pem.indexOf(footer)).replaceAll("\\s", ""));
            if (pkcs1) {
                byte[] octet = der(0x04, decoded);
                byte[] body = null;
                try {
                    body = concat(new byte[]{0x02, 0x01, 0x00}, RSA_ALGORITHM, octet);
                    encoded = der(0x30, body);
                } finally {
                    Arrays.fill(octet, (byte) 0);
                    if (body != null) Arrays.fill(body, (byte) 0);
                }
            } else {
                encoded = decoded;
            }
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalArgumentException("GITHUB_KEY_UNAVAILABLE");
        } finally {
            if (pemBytes != null) Arrays.fill(pemBytes, (byte) 0);
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] concat(byte[]... values) {
        int size = Arrays.stream(values).mapToInt(value -> value.length).sum();
        byte[] result = new byte[size];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static byte[] der(int tag, byte[] body) {
        int n = body.length;
        int lengthBytes = n < 128 ? 1 : n < 256 ? 2 : n < 65_536 ? 3 : 4;
        byte[] result = new byte[1 + lengthBytes + n];
        result[0] = (byte) tag;
        if (lengthBytes == 1) result[1] = (byte) n;
        else {
            result[1] = (byte) (0x80 | lengthBytes - 1);
            for (int i = 2; i <= lengthBytes; i++) result[i] = (byte) (n >> (8 * (lengthBytes - i)));
        }
        System.arraycopy(body, 0, result, 1 + lengthBytes, n);
        return result;
    }
}
