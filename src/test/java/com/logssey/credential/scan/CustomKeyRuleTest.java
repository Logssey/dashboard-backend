package com.logssey.credential.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 폼 입력 → 규칙 자동 생성, 그리고 스캐너가 내장 + 사용자 규칙을 함께 검사하는지 */
class CustomKeyRuleTest {

    private static final Fingerprinter FINGERPRINTER = new Fingerprinter("test-fingerprint-secret");
    // 형식만 맞춘 가짜 사내 키 (rik_ + 16진수 32자)
    private static final String RIK = "rik_" + "0123456789abcdef".repeat(2);
    private static final CustomKeyRule RIK_RULE =
            KeyRuleCompiler.build(1, "사내 RIK 키", "rik_", KeyCharset.HEX_LOWER, 32, true);

    @Test
    @DisplayName("접두사 + 문자 종류 + 길이로 정규식이 만들어진다")
    void buildsRegexFromForm() {
        assertThat(KeyRuleCompiler.readable("rik_", KeyCharset.HEX_LOWER, 32)).isEqualTo("rik_[0-9a-f]{32}");
        assertThat(RIK_RULE.pattern().matcher("key=" + RIK).find()).isTrue();
    }

    @Test
    @DisplayName("길이·문자 종류가 다르거나 다른 단어 중간이면 잡지 않는다")
    void matchesExactShapeOnly() {
        assertThat(SecretScanner.scan(RIK + "0", List.of(RIK_RULE))).isEmpty();           // 33자
        assertThat(SecretScanner.scan(RIK.substring(0, 35), List.of(RIK_RULE))).isEmpty(); // 31자
        assertThat(SecretScanner.scan(RIK.toUpperCase().replace("RIK_", "rik_"), List.of(RIK_RULE))).isEmpty(); // 대문자
        assertThat(SecretScanner.scan("xrik_" + RIK.substring(4), List.of(RIK_RULE))).isEmpty(); // 단어 중간
        assertThat(SecretScanner.scan("\"" + RIK + "\",", List.of(RIK_RULE))).hasSize(1);  // 따옴표 안은 잡는다
    }

    @Test
    @DisplayName("접두사의 . 은 정규식 문법이 아니라 글자 그대로 취급한다")
    void quotesPrefix() {
        CustomKeyRule dotted = KeyRuleCompiler.build(2, "점 접두사", "a.b", KeyCharset.DIGITS, 16, true);
        assertThat(SecretScanner.scan("a.b" + "1".repeat(16), List.of(dotted))).hasSize(1);
        assertThat(SecretScanner.scan("aXb" + "1".repeat(16), List.of(dotted))).isEmpty();
    }

    @Test
    @DisplayName("이상한 입력은 규칙을 만들지 않는다")
    void rejectsBadInput() {
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "r", KeyCharset.HEX, 32, true))
                .isInstanceOf(InvalidKeyRuleException.class).hasMessageContaining("접두사");
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "ri k", KeyCharset.HEX, 32, true))
                .hasMessageContaining("영문·숫자");
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "(.*)+", KeyCharset.HEX, 32, true))
                .isInstanceOf(InvalidKeyRuleException.class);
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "rik_", KeyCharset.HEX, 8, true))
                .hasMessageContaining("길이");
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "rik_", KeyCharset.HEX, 500, true))
                .hasMessageContaining("길이");
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", "AKIA", KeyCharset.ALNUM_UPPER, 16, true))
                .hasMessageContaining("기본 규칙");
        for (String reserved : new String[] {"ghp_", "GHO_", "ghs_x", "github_pat_", "secret_", "ntn_x"}) {
            assertThatThrownBy(() -> KeyRuleCompiler.build(0, "x", reserved, KeyCharset.ALNUM, 36, true))
                    .as(reserved).hasMessageContaining("기본 규칙");
        }
        // 비슷하지만 다른 접두사는 허용한다
        assertThat(KeyRuleCompiler.build(0, "x", "gh_", KeyCharset.ALNUM, 36, true)).isNotNull();
        assertThat(KeyRuleCompiler.build(0, "x", "my_secret_", KeyCharset.ALNUM, 36, true)).isNotNull();
        assertThatThrownBy(() -> KeyRuleCompiler.build(0, " ", "rik_", KeyCharset.HEX, 32, true))
                .hasMessageContaining("이름");
        assertThatThrownBy(() -> KeyRuleCompiler.validate("x", "rik_", null, 32))
                .hasMessageContaining("문자 종류");
    }

    @Test
    @DisplayName("내장 규칙(AWS·Notion)과 사용자 규칙을 함께 검사한다")
    void scansBuiltInAndCustomTogether() {
        String text = "AKIAIOSFODNN7EXAMPLE 그리고 " + RIK;
        List<SecretMatch> matches = SecretScanner.scan(text, List.of(RIK_RULE));

        assertThat(matches).extracting(SecretMatch::pattern).containsExactly(SecretPattern.AWS_ACCESS_KEY_ID, RIK_RULE);
        assertThat(SecretScanner.scan(text)).hasSize(1); // 사용자 규칙 없이 돌리면 기존과 동일
    }

    @Test
    @DisplayName("사용자 키도 마스킹·지문이 똑같이 적용된다 (원문 미저장)")
    void masksAndFingerprintsCustomKeys() {
        List<LeakedCredential> leaks = LeakGrouper.group(
                SecretScanner.scan(RIK, List.of(RIK_RULE)), "Notion 페이지: 테스트 (p1)", FINGERPRINTER);

        assertThat(leaks).hasSize(1);
        LeakedCredential leak = leaks.get(0);
        assertThat(leak.issuer()).isEqualTo("CUSTOM");
        assertThat(leak.credentialType()).isEqualTo("CUSTOM_KEY");
        assertThat(leak.maskedValue()).isEqualTo("rik_****cdef");
        assertThat(leak.displayName()).isEqualTo("사내 RIK 키 rik_****cdef");
        assertThat(leak.externalId()).isNull();
        assertThat(leak.fingerprint()).startsWith("hmac-sha256:v1:");
        assertThat(leak.toString()).doesNotContain(RIK);
    }

    @Test
    @DisplayName("식별자(비밀 아님)로 등록하면 지문 대신 식별자로 저장한다")
    void identifierRuleStoresExternalId() {
        CustomKeyRule idRule = KeyRuleCompiler.build(3, "사내 클라이언트 ID", "cid-", KeyCharset.ALNUM_UPPER, 16, false);
        String id = "cid-ABCDEF0123456789";

        LeakedCredential leak = LeakGrouper.group(SecretScanner.scan(id, List.of(idRule)), "loc", FINGERPRINTER).get(0);
        assertThat(leak.externalId()).isEqualTo(id);
        assertThat(leak.fingerprint()).isNull();
    }
}
