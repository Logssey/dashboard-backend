package com.logssey.local;

import javax.sql.DataSource;

import com.logssey.credential.event.CredentialRiskEventService;
import com.logssey.credential.scan.NotionLeakScanService;
import com.logssey.credential.scan.ScanResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * 로컬 개발용 샘플 데이터 적재기.
 *
 * - local 프로필에서만 만들어진다. 운영(프로필 없음)에서는 이 클래스가 아예 동작하지 않는다.
 * - 서버가 켜질 때마다(Flyway가 테이블을 만든 뒤) 기존 샘플을 지우고 다시 넣는다.
 * - 발생 시각은 SQL 안의 now() 기준이라, 켤 때마다 "최근 7일"로 다시 계산된다.
 * - 샘플을 넣은 뒤 키 위험 판단을 돌려, 키 관련 탐지 이벤트는 코드가 자동으로 만든다 (사람이 적지 않음).
 * - Notion 수집기 토큰이 .env에 있으면 그 전에 Notion 페이지를 스캔해 발견한 키도 함께 판단한다.
 * - 안전장치: DB 주소가 내 컴퓨터(localhost, 127.0.0.1)가 아니면 실행하지 않고 서버를 멈춘다.
 */
@Component
@Profile("local")
public class LocalSampleDataLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LocalSampleDataLoader.class);
    private static final String SAMPLE_SQL = "db/sample/local-sample-data.sql";

    private final DataSource dataSource;
    private final String datasourceUrl;
    private final CredentialRiskEventService credentialRiskEventService;
    private final NotionLeakScanService notionLeakScanService;

    public LocalSampleDataLoader(DataSource dataSource,
                                 @Value("${spring.datasource.url}") String datasourceUrl,
                                 CredentialRiskEventService credentialRiskEventService,
                                 NotionLeakScanService notionLeakScanService) {
        this.dataSource = dataSource;
        this.datasourceUrl = datasourceUrl;
        this.credentialRiskEventService = credentialRiskEventService;
        this.notionLeakScanService = notionLeakScanService;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!isLocalDatabase(datasourceUrl)) {
            throw new IllegalStateException(
                    "Local sample data can only be loaded into a local database (localhost, 127.0.0.1).");
        }

        ResourceDatabasePopulator populator = new ResourceDatabasePopulator(new ClassPathResource(SAMPLE_SQL));
        populator.setSqlScriptEncoding("UTF-8");
        DatabasePopulatorUtils.execute(populator, dataSource);

        // Notion 수집기가 설정돼 있으면 공유된 페이지를 스캔해 발견한 키를 저장한다. 실패해도 서버는 계속 켠다
        ScanResult scan = notionLeakScanService.collectLeaks();
        log.info("Notion leak scan on startup: status={}, pages={}, foundKeys={}",
                scan.status(), scan.scannedPages(), scan.foundKeys());

        int riskEvents = credentialRiskEventService.createRiskEvents();

        log.info("Local sample data reloaded: 8 assets, 5 credentials, 8 sample detection events"
                + " (detected_at = last 7 days from now), {} credential risk events (detected_at = now).", riskEvents);
    }

    static boolean isLocalDatabase(String url) {
        return url != null && (url.contains("//localhost:") || url.contains("//localhost/")
                || url.contains("//127.0.0.1:") || url.contains("//127.0.0.1/"));
    }
}
