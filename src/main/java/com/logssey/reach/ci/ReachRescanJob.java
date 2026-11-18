package com.logssey.reach.ci;

import java.time.LocalDate;
import java.time.ZoneId;

import com.logssey.reach.query.ReachQueryService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 하루 1번 재대조 (PRD FR-11, 명세 6-1 SCHEDULE). 운영에서 실행 중인 이미지(L1)의 스캔마다 SCHEDULE 검사를 만들고
 * 서비스 레포의 Reach 워크플로를 띄운다(ReachCiCheckService.createRescan). 러너는 보관한 SBOM을 최신 취약점 DB로 다시 대조하고
 * 같은 digest의 이미지에서 jar를 꺼내 L2로 판정한다. 재빌드는 없다.
 * 명세 6-1은 GitHub schedule 트리거였지만, 실행 중인 digest는 대시보드만 알아서 대시보드가 띄운다.
 * 기본은 한국 04:30으로 L1 수집(03:17) 뒤다. 바꾸려면 logssey.reach.rescan.cron, 끄려면 "-"
 */
@Component
public class ReachRescanJob {

    private static final Logger log = LoggerFactory.getLogger(ReachRescanJob.class);
    private static final ZoneId ZONE = ZoneId.of("Asia/Seoul");

    private final ReachQueryService query;
    private final ReachCiCheckService checks;

    public ReachRescanJob(ReachQueryService query, ReachCiCheckService checks) {
        this.query = query;
        this.checks = checks;
    }

    @Scheduled(cron = "${logssey.reach.rescan.cron:0 30 4 * * *}", zone = "Asia/Seoul")
    public void run() {
        run(LocalDate.now(ZONE));
    }

    /** 띄운 재대조 수. 한 스캔이 실패해도(띄우기 실패 등) 나머지는 띄운다 */
    int run(LocalDate day) {
        int dispatched = 0;
        for (long scanId : query.runningImageScanIds()) {
            try {
                var created = checks.createRescan(scanId, day);
                if (created.isEmpty()) return dispatched;   // 띄우는 설정이 없다
                if (!created.get().replayed()) {
                    dispatched++;
                    log.info("Reach rescan of scan {} dispatched as check {}", scanId, created.get().check().id());
                }
            } catch (RuntimeException e) {
                log.warn("Reach rescan of scan {} was not dispatched: {}", scanId, e.toString());
            }
        }
        return dispatched;
    }
}
