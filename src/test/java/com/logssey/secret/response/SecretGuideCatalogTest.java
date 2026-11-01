package com.logssey.secret.response;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretGuideCatalogTest {
    @Test
    void serverAuthoredDefaultsVaryByIssuerCredentialKindAndWorkflowStage() {
        var aws = SecretGuideCatalog.fallback(SecretGuideContext.of("AWS", "AWS_ACCESS_KEY_PAIR",
                "CONFIRMED", "OPEN", "UNCHECKED"));
        var github = SecretGuideCatalog.fallback(SecretGuideContext.of("GITHUB", "GITHUB_CLASSIC_PAT",
                "CONFIRMED", "IN_PROGRESS", "VALID"));
        var temporary = SecretGuideCatalog.fallback(SecretGuideContext.of("AWS", "AWS_TEMPORARY_CREDENTIALS",
                "CONFIRMED", "OPEN", "UNCHECKED"));
        var pending = SecretGuideCatalog.fallback(SecretGuideContext.of("GITHUB", "GITHUB_FINE_GRAINED_PAT",
                "CONFIRMED", "REVALIDATION_PENDING", "INVALID"));
        var resolved = SecretGuideCatalog.fallback(SecretGuideContext.of("AWS", "AWS_ACCESS_KEY_PAIR",
                "CONFIRMED", "RESOLVED", "INVALID"));
        assertThat(aws.title()).contains("AWS");
        assertThat(aws.steps()).anySatisfy(step -> assertThat(step.description()).contains("CloudTrail"));
        assertThat(github.title()).contains("GitHub");
        assertThat(github.steps().getFirst().title()).contains("진행 중");
        assertThat(temporary.steps()).anySatisfy(step -> assertThat(step.description()).contains("세션 차단"));
        assertThat(pending.steps().getFirst().description()).contains("해결 완료를 의미하지 않습니다");
        assertThat(resolved.steps().getFirst().title()).contains("해결 근거");
        assertThat(aws.steps()).filteredOn(step -> "RECORD_ACTION".equals(step.code()))
                .singleElement().satisfies(step -> assertThat(step.description())
                        .contains("발견 위치의 키 원문을 제거", "키 폐기도 별도로 확인", "기록하세요"));
        for (var guide : List.of(pending, resolved)) {
            assertThat(guide.steps()).filteredOn(step -> "RECORD_ACTION".equals(step.code()))
                    .singleElement().satisfies(step -> assertThat(step.description())
                            .contains("발견 위치의 키 원문 제거", "확인")
                            .doesNotContain("제거하고", "옮기세요"));
        }
        for (var guide : List.of(aws, github, temporary, pending, resolved)) {
            assertThat(guide.source()).isEqualTo("DEFAULT");
            assertThat(guide.steps()).allSatisfy(step -> assertThat(step.description().length()).isLessThanOrEqualTo(160));
        }
    }

    @Test
    void rejectsUnknownOrUnsafeOrderAndBoundsAllDisplayedCopy() {
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE", "DELETE_EVERYTHING"))).isEmpty();
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "RECORD_ACTION", "EXTERNAL_ROTATION", "REVALIDATE"))).isEmpty();
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE", "REVALIDATE"))).isEmpty();

        var guide = SecretGuideCatalog.fallback();
        assertThat(guide.steps()).hasSizeBetween(4, 6);
        assertThat(guide.title().length()).isLessThanOrEqualTo(80);
        assertThat(guide.notice().length()).isLessThanOrEqualTo(160);
        assertThat(guide.steps()).allSatisfy(step -> {
            assertThat(step.title().length()).isLessThanOrEqualTo(80);
            assertThat(step.description().length()).isLessThanOrEqualTo(160);
        });
    }
}
