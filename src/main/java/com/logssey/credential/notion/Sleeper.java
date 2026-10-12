package com.logssey.credential.notion;

import java.time.Duration;

/** 429 대기를 바꿔 끼울 수 있게 분리한다. 테스트에서는 실제로 기다리지 않고 기록만 한다 */
@FunctionalInterface
public interface Sleeper {

    void sleep(Duration duration);

    static Sleeper real() {
        return duration -> {
            try {
                Thread.sleep(duration.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for Notion rate limit", e);
            }
        };
    }
}
