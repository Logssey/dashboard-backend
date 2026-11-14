package com.logssey.secret.query;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import com.logssey.common.error.ApiException;

class SecretSafeSearchTest {
    @Test void boundedPublicTextAllowsPathsMasksAndUnicodeWithoutAliasRestrictions() {
        assertThat(SecretSafeSearch.normalize("  주문/app.env · ••••1234  ")).isEqualTo("주문/app.env · ••••1234");
        assertThat(SecretSafeSearch.matches("App.env", "주문/app.env · 위치 #3")).isTrue();
        assertThat(SecretSafeSearch.normalize("  ")).isNull();
    }
    @Test void credentialLikeAndOversizedQueriesAreRejectedBeforeSnapshotPersistence() {
        for(String q:java.util.List.of("ghp_"+"x".repeat(36),"github_pat_secret","AKIA"+"X".repeat(16),"ntn_"+"x".repeat(32),"가".repeat(101),"a\nb"))
            assertThatThrownBy(()->SecretSafeSearch.normalize(q)).isInstanceOf(ApiException.class);
    }
}
