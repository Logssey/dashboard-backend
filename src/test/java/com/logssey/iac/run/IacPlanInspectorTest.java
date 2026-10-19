package com.logssey.iac.run;

import java.nio.charset.StandardCharsets;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.junit.jupiter.api.Test;

import static com.logssey.iac.run.IacPlanFixtures.gzip;
import static com.logssey.iac.run.IacPlanFixtures.gzipResource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IacPlanInspectorTest {

    private final IacPlanInspector inspector = new IacPlanInspector();

    @Test
    void acceptsAPlanScrubbedByTheRunner() {
        var plan = inspector.inspect(gzipResource("plan-scrubbed.json"));
        assertThat(plan.path("resource_changes").size()).isEqualTo(3);
    }

    @Test
    void rejectsTheSamePlanBeforeScrubbing() {
        assertThatThrownBy(() -> inspector.inspect(gzipResource("plan-raw.json")))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.UNPROCESSABLE))
                .hasMessage("민감값이 남아 있습니다.");
    }

    @Test
    void rejectsASingleLeftoverInsideANestedAttribute() {
        String plan = """
                {"format_version":"1.2","resource_changes":[{"change":{
                  "before":null,"before_sensitive":false,
                  "after":{"input":{"password":"(sensitive)","tags":["a","left-over"]}},
                  "after_sensitive":{"input":{"password":true,"tags":[false,true]}}}}]}
                """;
        assertThatThrownBy(() -> inspector.inspect(gzip(plan.getBytes(StandardCharsets.UTF_8))))
                .hasMessage("민감값이 남아 있습니다.");
    }

    @Test
    void rejectsSomethingThatIsNotAPlan() {
        assertThatThrownBy(() -> inspector.inspect("not gzip".getBytes(StandardCharsets.UTF_8)))
                .hasMessage("plan JSON 형식이 아닙니다.");
        assertThatThrownBy(() -> inspector.inspect(gzip("{\"resource_changes\":[]}".getBytes(StandardCharsets.UTF_8))))
                .hasMessage("plan JSON 형식이 아닙니다.");
        assertThatThrownBy(() -> inspector.inspect(gzip("[1,2]".getBytes(StandardCharsets.UTF_8))))
                .hasMessage("plan JSON 형식이 아닙니다.");
    }

    @Test
    void rejectsADecompressionBomb() {
        byte[] bomb = gzip(new byte[IacPlanInspector.MAX_JSON_BYTES + 1]);
        assertThat(bomb.length).isLessThan(IacPlanInspector.MAX_COMPRESSED_BYTES);
        assertThatThrownBy(() -> inspector.inspect(bomb))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.PAYLOAD_TOO_LARGE));
    }
}
