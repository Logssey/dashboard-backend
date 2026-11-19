package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HelpQuestionGuardTest {

    @Test
    void detectsCredentialShapedValues() {
        assertThat(HelpQuestionGuard.containsSecretLikeValue("이 키 맞나요? " + HelpTestKeys.anthropicLike())).isTrue();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("토큰 " + HelpTestKeys.githubLike() + " 등록법")).isTrue();
        assertThat(HelpQuestionGuard.containsSecretLikeValue(HelpTestKeys.awsAccessKeyLike() + " 는 어디서 봐요")).isTrue();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("값: " + HelpTestKeys.opaqueToken())).isTrue();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("-----BEGIN RSA PRIVATE KEY-----")).isTrue();
    }

    @Test
    void allowsOrdinaryUsageQuestions() {
        assertThat(HelpQuestionGuard.containsSecretLikeValue("대응 건은 어떻게 만들어요?")).isFalse();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("GitHub 연결을 추가하려면 어디로 가요?")).isFalse();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("AKIA로 시작하는 키 형식은 어떻게 등록해요?")).isFalse();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("CSV 내보내기 버튼이 안 보여요")).isFalse();
        assertThat(HelpQuestionGuard.containsSecretLikeValue("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")).isFalse();
    }
}
