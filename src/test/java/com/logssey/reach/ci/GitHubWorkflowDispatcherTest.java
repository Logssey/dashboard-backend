package com.logssey.reach.ci;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import com.logssey.reach.ci.auth.ReachCiProperties;

import org.junit.jupiter.api.Test;

/** 앱 개인 키 읽기와 설정 여부. GitHub 호출은 ReachScanDispatchIntegrationTest */
class GitHubWorkflowDispatcherTest {

    @Test
    void readsTheGitHubPkcs1KeyAndThePkcs8Key() throws NoSuchAlgorithmException {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var key = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();
        byte[] pkcs8 = key.getEncoded();

        // GitHub이 내려 주는 형식(PKCS#1, "RSA PRIVATE KEY")과 openssl pkcs8로 바꾼 형식
        var fromPkcs1 = GitHubWorkflowDispatcher.privateKey(pem("RSA PRIVATE KEY", pkcs1(pkcs8)));
        var fromPkcs8 = GitHubWorkflowDispatcher.privateKey(pem("PRIVATE KEY", pkcs8));
        assertThat(fromPkcs1.getModulus()).isEqualTo(key.getModulus());
        assertThat(fromPkcs1.getPrivateExponent()).isEqualTo(key.getPrivateExponent());
        assertThat(fromPkcs8.getPrivateExponent()).isEqualTo(key.getPrivateExponent());

        // 파일 끝 줄바꿈·CRLF가 있어도 된다
        assertThat(GitHubWorkflowDispatcher.privateKey(pem("RSA PRIVATE KEY", pkcs1(pkcs8)).replace("\n", "\r\n") + "\r\n")
                .getModulus()).isEqualTo(key.getModulus());
    }

    @Test
    void aBrokenKeyStopsStartupAndNoKeyMeansNoDispatch() {
        assertThatThrownBy(() -> GitHubWorkflowDispatcher.privateKey("-----BEGIN RSA PRIVATE KEY-----\nnot base64!\n"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("logssey.reach.dispatch.private-key");
        assertThatThrownBy(() -> new GitHubWorkflowDispatcher(
                new ReachDispatchProperties("1", pem("PRIVATE KEY", new byte[] {1, 2, 3}), null, null),
                new ReachCiProperties("Logssey", null, null)))
                .isInstanceOf(IllegalStateException.class);

        var none = new GitHubWorkflowDispatcher(ReachDispatchProperties.closed(), new ReachCiProperties("Logssey", null, null));
        assertThat(none.enabled()).isFalse();
        assertThatThrownBy(() -> none.dispatch("service-backend", Map.of())).isInstanceOf(IllegalStateException.class);
    }

    private static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    /** PKCS#8 PrivateKeyInfo에서 PKCS#1 RSAPrivateKey(마지막 OCTET STRING의 내용)를 꺼낸다 */
    private static byte[] pkcs1(byte[] pkcs8) {
        int i = 1 + lengthBytes(pkcs8, 1);           // 바깥 SEQUENCE 머리
        i += 3;                                      // version INTEGER 0
        i += 2 + (pkcs8[i + 1] & 0xff);              // AlgorithmIdentifier SEQUENCE
        assertThat(pkcs8[i]).isEqualTo((byte) 0x04); // OCTET STRING
        int length = length(pkcs8, i + 1);
        int start = i + 1 + lengthBytes(pkcs8, i + 1);
        return Arrays.copyOfRange(pkcs8, start, start + length);
    }

    private static int lengthBytes(byte[] der, int at) {
        int first = der[at] & 0xff;
        return first < 0x80 ? 1 : 1 + (first & 0x7f);
    }

    private static int length(byte[] der, int at) {
        int first = der[at] & 0xff;
        if (first < 0x80) return first;
        int value = 0;
        for (int k = 1; k <= (first & 0x7f); k++) value = (value << 8) | (der[at + k] & 0xff);
        return value;
    }
}
