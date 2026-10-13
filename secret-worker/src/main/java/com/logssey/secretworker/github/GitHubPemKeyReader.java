package com.logssey.secretworker.github;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Reads GitHub-generated PKCS#1 or standard PKCS#8 RSA PEM without exposing its bytes in exceptions. */
final class GitHubPemKeyReader {
    private static final byte[] RSA_ALGORITHM = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };

    private GitHubPemKeyReader() { }

    static PrivateKey read(Path path) {
        byte[] pemBytes = null;
        byte[] decoded = null;
        byte[] encoded = null;
        try {
            try (var stream = Files.newInputStream(path)) {
                pemBytes = stream.readNBytes(32_769);
            }
            if (pemBytes.length > 32_768) {
                throw new IllegalArgumentException("GitHub App private key is too large");
            }
            String pem = new String(pemBytes, java.nio.charset.StandardCharsets.US_ASCII);
            boolean pkcs1 = pem.contains("-----BEGIN RSA PRIVATE KEY-----")
                    && pem.contains("-----END RSA PRIVATE KEY-----");
            boolean pkcs8 = pem.contains("-----BEGIN PRIVATE KEY-----")
                    && pem.contains("-----END PRIVATE KEY-----");
            if (pkcs1 == pkcs8) {
                throw new IllegalArgumentException("Unsupported GitHub App private key format");
            }
            String header = pkcs1 ? "-----BEGIN RSA PRIVATE KEY-----" : "-----BEGIN PRIVATE KEY-----";
            String footer = pkcs1 ? "-----END RSA PRIVATE KEY-----" : "-----END PRIVATE KEY-----";
            String base64 = pem.substring(pem.indexOf(header) + header.length(), pem.indexOf(footer))
                    .replaceAll("\\s", "");
            decoded = Base64.getDecoder().decode(base64);
            if (pkcs1) {
                byte[] octet = octetString(decoded);
                try {
                    encoded = sequence(integerZero(), RSA_ALGORITHM, octet);
                } finally {
                    Arrays.fill(octet, (byte) 0);
                }
            } else {
                encoded = decoded;
            }
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (IOException | java.security.GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("Unable to load GitHub App private key");
        } finally {
            if (pemBytes != null) Arrays.fill(pemBytes, (byte) 0);
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] integerZero() { return new byte[]{0x02, 0x01, 0x00}; }
    private static byte[] octetString(byte[] value) { return der(0x04, value); }
    private static byte[] sequence(byte[]... values) {
        int length = Arrays.stream(values).mapToInt(a -> a.length).sum();
        byte[] body = new byte[length];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, body, offset, value.length);
            offset += value.length;
        }
        try {
            return der(0x30, body);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    private static byte[] der(int tag, byte[] value) {
        int n = value.length;
        int lengthBytes = n < 128 ? 1 : n < 256 ? 2 : n < 65_536 ? 3 : 4;
        byte[] result = new byte[1 + lengthBytes + n];
        result[0] = (byte) tag;
        if (lengthBytes == 1) {
            result[1] = (byte) n;
        } else {
            result[1] = (byte) (0x80 | lengthBytes - 1);
            for (int i = 2; i <= lengthBytes; i++) result[i] = (byte) (n >> (8 * (lengthBytes - i)));
        }
        System.arraycopy(value, 0, result, 1 + lengthBytes, n);
        return result;
    }
}
