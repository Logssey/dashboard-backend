package com.logssey.reach.l1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 6시간마다 Finding deployment를 다시 계산한다. 수집이 끊기면 조회가 오래돼 UNKNOWN으로 바뀌어야 하기 때문이다(PRD FR-04).
 * 수집은 6시간마다(ARD 7-3 A, gitops reach/l1)이고, 6시간이면 신선도(48시간)를 넘긴 조회를 늦어도 6시간 안에 UNKNOWN으로 바꾼다.
 * 주기 기본값은 식 안에 둔다(공용 application.properties를 고치지 않으려고). 바꾸려면 logssey.reach.l1.recompute-cron
 */
@Component
public class ReachL1RecomputeJob {

    private static final Logger log = LoggerFactory.getLogger(ReachL1RecomputeJob.class);

    private final ReachL1Service service;

    public ReachL1RecomputeJob(ReachL1Service service) {
        this.service = service;
    }

    @Scheduled(cron = "${logssey.reach.l1.recompute-cron:0 5 */6 * * *}", zone = "UTC")
    public void run() {
        int updated = service.recompute(null);
        if (updated > 0) {
            log.info("Reach L1 recompute changed deployment of {} findings", updated);
        }
    }
}
