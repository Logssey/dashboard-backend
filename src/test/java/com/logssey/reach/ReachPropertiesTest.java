package com.logssey.reach;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.logssey.reach.ReachProperties.App;
import com.logssey.reach.ReachProperties.L1;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachPropertiesTest {

    @Test
    void emptyConfigurationStartsWithNothingRegisteredAndL1Off() {
        var empty = new ReachProperties(null, null);
        assertThat(empty.apps()).isEmpty();
        assertThat(empty.codes()).isEmpty();
        assertThat(empty.l1().enabled()).isFalse();
        assertThat(empty.appOfRepo("service-backend", null)).isEmpty();
        assertThat(empty.appOfImage("logssey/reused-api")).isEmpty();
    }

    @Test
    void mapsReposWithOwnerAndPathFallbackAndImagesExactly() {
        var reused = ReachTestProperties.REUSED;
        assertThat(reused.codes()).containsExactly("API", "WEB", "CHAT");
        assertThat(reused.appOfRepo("Logssey/service-backend", null)).hasValue("API");
        assertThat(reused.appOfRepo("service-backend", "chat-server")).hasValue("CHAT");
        assertThat(reused.appOfRepo("service-backend", "docs")).hasValue("API");   // 경로가 없으면 레포 전체 등록으로
        assertThat(reused.appOfRepo("service-frontend", "x")).hasValue("WEB");
        assertThat(reused.appOfRepo("unknown", null)).isEmpty();
        assertThat(reused.appOfImage("logssey/reused-chat")).hasValue("CHAT");
        assertThat(reused.appOfImage("reused-chat")).isEmpty();
        assertThat(reused.l1().enabled()).isTrue();
    }

    @Test
    void onlyAPathRegistrationDoesNotCoverTheWholeRepo() {
        var props = new ReachProperties(List.of(new App("BATCH", "order-service", "batch", null)), null);
        assertThat(props.appOfRepo("order-service", "batch")).hasValue("BATCH");
        assertThat(props.appOfRepo("order-service", null)).isEmpty();
    }

    @Test
    void badConfigurationStopsStartup() {
        for (var apps : List.of(
                List.of(new App("api", "r", null, null)),                       // 소문자
                List.of(new App("ABCDEFGHIJK", "r", null, null)),               // 11자 (V47·VARCHAR(10))
                List.of(new App(null, "r", null, null)),
                List.of(new App("API", null, null, null)),                      // 레포도 이미지도 없음
                List.of(new App("API", "r", null, null), new App("API", "s", null, null)),
                List.of(new App("A", "org/r", null, null), new App("B", "r", null, null)),   // 소유자만 다른 같은 레포
                List.of(new App("A", null, null, "i"), new App("B", null, null, "i")))) {
            assertThatThrownBy(() -> new ReachProperties(apps, null)).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void l1NeedsBothClusterAndNamespaces() {
        assertThat(new L1("c", List.of("ns")).enabled()).isTrue();
        assertThat(new L1("c", null).enabled()).isFalse();
        assertThat(new L1(" ", List.of("ns")).enabled()).isFalse();
        assertThat(new L1(null, List.of("ns")).enabled()).isFalse();
    }
}
