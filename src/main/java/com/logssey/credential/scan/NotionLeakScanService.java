package com.logssey.credential.scan;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import com.logssey.credential.notion.Sleeper;
import com.logssey.credential.scan.notion.NotionPage;
import com.logssey.credential.scan.notion.NotionPageReader;
import com.logssey.credential.scan.notion.NotionReadException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Notion 페이지 유출 탐지 (Notion 키 관리 연동 4번 작업).
 *
 * 1. 수집기에 공유된 페이지 목록을 받는다
 * 2. 페이지마다 Markdown 글을 받아 키 형식을 찾는다
 * 3. 찾은 키를 원문 없이 credentials에 저장한다 (source = SCAN)
 *
 * Secret 기준 문서에 맞춰 탐지 이벤트(detection_events)는 만들지 않는다. 등급도 매기지 않는다 (미평가).
 * 읽지 못한 페이지는 "키 0개"로 치지 않고 따로 센다 (PARTIAL).
 *
 * 토큰이나 지문 비밀값이 .env에 없으면 아무것도 하지 않는다. 페이지 내용과 찾은 원문은 로그에 남기지 않는다.
 */
@Service
public class NotionLeakScanService {

    private static final Logger log = LoggerFactory.getLogger(NotionLeakScanService.class);
    private static final int MAX_TITLE_LENGTH = 200;

    private final String token;
    private final String baseUrl;
    private final String fingerprintSecret;
    private final LeakCredentialRepository leakRepository;
    private final CustomKeyPatternRepository customPatterns;
    private final Clock clock = Clock.systemUTC();

    public NotionLeakScanService(@Value("${logssey.notion.collector.token:}") String token,
                                 @Value("${logssey.notion.collector.base-url:" + NotionPageReader.REAL_BASE_URL + "}") String baseUrl,
                                 @Value("${logssey.credential.fingerprint-secret:}") String fingerprintSecret,
                                 LeakCredentialRepository leakRepository,
                                 CustomKeyPatternRepository customPatterns) {
        this.token = token;
        this.baseUrl = baseUrl;
        this.fingerprintSecret = fingerprintSecret;
        this.leakRepository = leakRepository;
        this.customPatterns = customPatterns;
    }

    public boolean isConfigured() {
        return !token.isBlank() && !fingerprintSecret.isBlank();
    }

    /** "지금 스캔"과 서버 시작 시 스캔이 같이 쓴다. 페이지를 읽어 발견한 키를 저장한다 */
    public synchronized ScanResult collectLeaks() {
        Instant now = clock.instant();
        String scannedAt = now.truncatedTo(ChronoUnit.SECONDS).toString();
        if (!isConfigured()) {
            log.info("Notion leak scan skipped. NOTION_COLLECTOR_TOKEN or CREDENTIAL_FINGERPRINT_SECRET is not set.");
            return new ScanResult("NOT_CONFIGURED", 0, 0, 0, 0,
                    ".env에 NOTION_COLLECTOR_TOKEN과 CREDENTIAL_FINGERPRINT_SECRET을 설정해 주세요.", scannedAt);
        }

        NotionPageReader reader = new NotionPageReader(baseUrl, token, Sleeper.real());
        Fingerprinter fingerprinter = new Fingerprinter(fingerprintSecret);
        // 스캔 시작 시점의 사용자 등록 규칙을 한 번 읽는다 (스캔 도중 등록·삭제해도 이번 스캔은 같은 규칙으로 끝낸다)
        List<CustomKeyRule> customRules = customPatterns.findAllRules();
        try {
            List<NotionPage> pages = reader.listSharedPages();
            List<LeakedCredential> leaks = new ArrayList<>();
            int scannedPages = 0;
            int unreadablePages = 0;
            for (NotionPage page : pages) {
                String markdown;
                try {
                    markdown = reader.readMarkdown(page.id());
                } catch (NotionReadException e) {
                    if (e.httpStatus() == 404) {
                        // 공유가 끊겼거나 지워진 페이지. 읽지 못한 범위로 센다 (0개로 치지 않음)
                        unreadablePages++;
                        continue;
                    }
                    throw e;
                }
                scannedPages++;
                leaks.addAll(LeakGrouper.group(SecretScanner.scan(markdown, customRules), location(page), fingerprinter));
            }

            int newKeys = 0;
            for (LeakedCredential leak : leaks) {
                if (leakRepository.upsert(leak, now)) {
                    newKeys++;
                }
            }
            log.info("Notion leak scan finished. pages={}, unreadablePages={}, foundKeys={}, newKeys={}",
                    scannedPages, unreadablePages, leaks.size(), newKeys);
            String message = "페이지 %d개를 검사해 키 %d개를 찾았어요.".formatted(scannedPages, leaks.size());
            if (unreadablePages > 0) {
                return new ScanResult("PARTIAL", scannedPages, unreadablePages, leaks.size(), newKeys,
                        message + " 읽지 못한 페이지 %d개는 검사하지 못했어요.".formatted(unreadablePages), scannedAt);
            }
            return new ScanResult("COMPLETED", scannedPages, 0, leaks.size(), newKeys, message, scannedAt);
        } catch (NotionReadException e) {
            log.warn("Notion leak scan failed. httpStatus={}, code={}", e.httpStatus(), e.code());
            return new ScanResult("FAILED", 0, 0, 0, 0, failureMessage(e), scannedAt);
        } catch (RuntimeException e) {
            log.warn("Notion leak scan failed. reason={}", e.getClass().getSimpleName());
            return new ScanResult("FAILED", 0, 0, 0, 0, "Notion에 연결하지 못했어요. 잠시 후 다시 시도해 주세요.", scannedAt);
        }
    }

    private static String location(NotionPage page) {
        String title = page.title().length() > MAX_TITLE_LENGTH
                ? page.title().substring(0, MAX_TITLE_LENGTH) + "…"
                : page.title();
        return "Notion 페이지: " + title + " (" + page.id() + ")";
    }

    private static String failureMessage(NotionReadException e) {
        return switch (e.httpStatus()) {
            case 401 -> "Notion 수집기 토큰이 유효하지 않아요. .env의 NOTION_COLLECTOR_TOKEN을 확인해 주세요.";
            case 403 -> "Notion 수집기에 콘텐츠 읽기 권한이 없어요. 수집기 설정에서 Read content를 켜 주세요.";
            case 429 -> "Notion 호출 한도를 넘었어요. 잠시 후 다시 시도해 주세요.";
            default -> "Notion 응답을 처리하지 못했어요. 잠시 후 다시 시도해 주세요.";
        };
    }
}
