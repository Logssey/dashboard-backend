package com.logssey.reach.ci;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 결과가 오지 않는 CI 스캔 정리 (명세 2-7·API-12). 러너가 결과도 실패 묶음도 올리지 못하면(작업 취소, 러너 장애,
 * 띄운 워크플로가 시작하지 않음) 스캔이 QUEUED·RUNNING에 영원히 남는다. 30분마다 logssey.reach.stale.after(기본 2시간,
 * 워크플로 timeout 30분보다 넉넉히)보다 오래된 것을 FAILED(RUNNER_NO_RESULT)로 끝낸다.
 * 끝난 검사는 같은 멱등 키로 다시 만들 수 있어, 같은 빌드를 다시 돌리면(Re-run) 새로 스캔한다.
 * 끄려면 logssey.reach.stale.cron을 "-"로
 */
@Component
public class ReachStaleScanJob {

    private static final Logger log = LoggerFactory.getLogger(ReachStaleScanJob.class);

    private final ReachCiCheckService checks;
    private final Duration after;

    public ReachStaleScanJob(ReachCiCheckService checks, @Value("${logssey.reach.stale.after:PT2H}") Duration after) {
        this.checks = checks;
        this.after = after;
    }

    @Scheduled(cron = "${logssey.reach.stale.cron:0 */30 * * * *}", zone = "Asia/Seoul")
    public void run() {
        int failed = checks.failStaleScans(after);
        if (failed > 0) log.warn("Reach: {} scans had no result from the runner within {} and were marked FAILED", failed, after);
    }
}
