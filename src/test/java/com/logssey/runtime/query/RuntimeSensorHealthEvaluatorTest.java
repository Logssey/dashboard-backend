package com.logssey.runtime.query;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import com.logssey.runtime.query.dto.RuntimeSensorListResponse.SensorItem;

import org.junit.jupiter.api.Test;

class RuntimeSensorHealthEvaluatorTest {

    private final RuntimeSensorHealthEvaluator evaluator = new RuntimeSensorHealthEvaluator(
            Duration.ofMinutes(2), Duration.ofMinutes(5));
    private final Instant now = Instant.parse("2026-10-14T06:00:00Z");

    @Test
    void changesSensorStateAsHeartbeatGetsStale() {
        assertThat(evaluator.evaluate(sensor(now.minusSeconds(60).toString(), null), now).status())
                .isEqualTo("HEALTHY");
        assertThat(evaluator.evaluate(sensor(now.minusSeconds(180).toString(), null), now).status())
                .isEqualTo("DEGRADED");
        assertThat(evaluator.evaluate(sensor(now.minusSeconds(360).toString(), null), now).status())
                .isEqualTo("OFFLINE");
    }

    @Test
    void eventWithoutHeartbeatIsVisibleButDegraded() {
        SensorItem result = evaluator.evaluate(sensor(null, now.minusSeconds(10).toString()), now);

        assertThat(result.status()).isEqualTo("DEGRADED");
    }

    @Test
    void sensorWithoutHeartbeatOrEventIsUnknown() {
        assertThat(evaluator.evaluate(sensor(null, null), now).status()).isEqualTo("UNKNOWN");
    }

    private static SensorItem sensor(String heartbeatAt, String eventAt) {
        return new SensorItem(1, "logssey-prod", "worker-a", "FALCO", "0.45.0",
                "modern_ebpf", "HEALTHY", heartbeatAt, eventAt, "runtime-rules-0.1.0", 0L, null);
    }
}
