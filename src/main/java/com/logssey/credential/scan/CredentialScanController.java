package com.logssey.credential.scan;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 시크릿 보안 탭의 "지금 스캔" (API 명세: 키 스캔 실행). 로그인 + CSRF 필요 */
@RestController
@RequestMapping("/api/v1/credentials")
public class CredentialScanController {

    private final NotionLeakScanService scanService;

    public CredentialScanController(NotionLeakScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public ScanResult scan() {
        return scanService.scanNow();
    }
}
