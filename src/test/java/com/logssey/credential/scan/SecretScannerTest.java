package com.logssey.credential.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 키 형식 찾기, 마스킹, 키 단위로 묶기, 지문 */
class SecretScannerTest {

    // AWS가 문서 예시로 공개한 가짜 값
    private static final String AWS_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    // 형식만 맞춘 가짜 Notion 토큰 (ntn_ + 46자)
    private static final String NOTION_TOKEN = "ntn_" + "a1B2c3D4e5".repeat(4) + "F6g7H8";
    private static final Fingerprinter FINGERPRINTER = new Fingerprinter("test-fingerprint-secret");

    @Test
    @DisplayName("AWS Access Key ID, Secret Access Key(이름이 붙은 경우), Notion 토큰을 찾는다")
    void findsAllPatterns() {
        String text = """
                # 회의록
                AWS_ACCESS_KEY_ID=%s
                aws_secret_access_key: "%s"
                notion token is %s
                """.formatted(AWS_ID, AWS_SECRET, NOTION_TOKEN);

        List<SecretMatch> matches = SecretScanner.scan(text);

        assertThat(matches).extracting(SecretMatch::pattern).containsExactly(
                SecretPattern.AWS_ACCESS_KEY_ID, SecretPattern.AWS_SECRET_ACCESS_KEY, SecretPattern.NOTION_TOKEN);
        assertThat(matches).extracting(SecretMatch::value).containsExactly(AWS_ID, AWS_SECRET, NOTION_TOKEN);
    }

    @Test
    @DisplayName("이름 없이 적힌 40자 문자열은 AWS Secret으로 보지 않는다 (과탐지 방지)")
    void ignoresUnlabeledFortyCharacters() {
        assertThat(SecretScanner.scan("random " + AWS_SECRET + " text")).isEmpty();
        assertThat(SecretScanner.scan("AKIA로 시작하는 키를 조심하세요. ntn_ 접두사도요.")).isEmpty();
    }

    @Test
    @DisplayName("같은 값이 여러 번 나와도 한 번만 돌려준다")
    void deduplicates() {
        assertThat(SecretScanner.scan(AWS_ID + " " + AWS_ID)).hasSize(1);
    }

    @Test
    @DisplayName("마스킹: 식별자·토큰은 앞 4자와 끝 4자, AWS Secret은 끝 4자만. toString에도 원문이 없다")
    void masksValues() {
        List<SecretMatch> matches = SecretScanner.scan(
                "AWS_ACCESS_KEY_ID=" + AWS_ID + "\nAWS_SECRET_ACCESS_KEY=" + AWS_SECRET + "\n" + NOTION_TOKEN);

        assertThat(matches).extracting(SecretMatch::masked).containsExactly("AKIA****MPLE", "****EKEY", "ntn_****g7H8");
        assertThat(matches.toString()).doesNotContain(AWS_SECRET).doesNotContain(NOTION_TOKEN);
    }

    @Test
    @DisplayName("묶기: ID + Secret은 비밀값이 보인 AWS 키 하나, ID만 있으면 지문 없음, Notion 토큰은 비밀값이 보인 키")
    void groupsIntoCredentials() {
        String location = "Notion 페이지: 테스트 (page-1)";

        List<LeakedCredential> pair = LeakGrouper.group(SecretScanner.scan(
                "AWS_ACCESS_KEY_ID=" + AWS_ID + "\nAWS_SECRET_ACCESS_KEY=" + AWS_SECRET), location, FINGERPRINTER);
        assertThat(pair).hasSize(1);
        assertThat(pair.get(0).externalId()).isEqualTo(AWS_ID);
        assertThat(pair.get(0).secretExposed()).isTrue();
        assertThat(pair.get(0).storageLocation()).isEqualTo(location);

        List<LeakedCredential> idOnly = LeakGrouper.group(SecretScanner.scan(AWS_ID), location, FINGERPRINTER);
        assertThat(idOnly.get(0).secretExposed()).isFalse();
        assertThat(idOnly.get(0).fingerprint()).isNull();

        List<LeakedCredential> notion = LeakGrouper.group(SecretScanner.scan(NOTION_TOKEN), location, FINGERPRINTER);
        assertThat(notion.get(0).issuer()).isEqualTo("NOTION");
        assertThat(notion.get(0).externalId()).isNull();
        assertThat(notion.get(0).secretExposed()).isTrue();
    }

    @Test
    @DisplayName("지문: 같은 값은 같은 지문, 비밀값이 다르면 다른 지문, 원문은 들어 있지 않다")
    void fingerprints() {
        String first = FINGERPRINTER.fingerprint(AWS_SECRET);

        assertThat(FINGERPRINTER.fingerprint(AWS_SECRET)).isEqualTo(first);
        assertThat(new Fingerprinter("other-secret").fingerprint(AWS_SECRET)).isNotEqualTo(first);
        assertThat(first).startsWith("hmac-sha256:v1:").doesNotContain(AWS_SECRET);
        assertThat(first.length()).isLessThanOrEqualTo(100);
    }
}
