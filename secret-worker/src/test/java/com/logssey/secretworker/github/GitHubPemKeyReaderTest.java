package com.logssey.secretworker.github;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GitHubPemKeyReaderTest {
    @TempDir Path temp;

    @Test
    void readsGithubStylePkcs1KeyWithoutDependingOnExternalTools() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        var privateKey = (RSAPrivateCrtKey) pair.getPrivate();
        byte[] pkcs1 = sequence(
                integer(BigInteger.ZERO), integer(privateKey.getModulus()),
                integer(privateKey.getPublicExponent()), integer(privateKey.getPrivateExponent()),
                integer(privateKey.getPrimeP()), integer(privateKey.getPrimeQ()),
                integer(privateKey.getPrimeExponentP()), integer(privateKey.getPrimeExponentQ()),
                integer(privateKey.getCrtCoefficient()));
        String pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs1)
                + "\n-----END RSA PRIVATE KEY-----\n";
        Path path = temp.resolve("app-key.pem");
        Files.writeString(path, pem);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(GitHubPemKeyReader.read(path));
        signer.update("fixture".getBytes(StandardCharsets.UTF_8));
        byte[] signed = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update("fixture".getBytes(StandardCharsets.UTF_8));
        assertThat(verifier.verify(signed)).isTrue();
    }

    private static byte[] integer(BigInteger value) { return tlv(0x02, value.toByteArray()); }

    private static byte[] sequence(byte[]... values) {
        var body = new ByteArrayOutputStream();
        for (byte[] value : values) body.writeBytes(value);
        return tlv(0x30, body.toByteArray());
    }

    private static byte[] tlv(int tag, byte[] value) {
        var out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 128) {
            out.write(value.length);
        } else if (value.length < 256) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write(value.length >> 8);
            out.write(value.length);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }
}
