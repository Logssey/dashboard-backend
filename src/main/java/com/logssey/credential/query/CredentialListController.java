package com.logssey.credential.query;

import com.logssey.credential.query.dto.response.CredentialListResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 시크릿 보안 탭 API (API 명세 CREDENTIALS). 로그인 필요 */
@RestController
@RequestMapping("/api/v1/credentials")
public class CredentialListController {

    private final CredentialListService credentialListService;

    public CredentialListController(CredentialListService credentialListService) {
        this.credentialListService = credentialListService;
    }

    @GetMapping
    public CredentialListResponse credentials(@RequestParam(defaultValue = "ALL") String issuer,
                                              @RequestParam(defaultValue = "ALL") String status,
                                              @RequestParam(defaultValue = "false") boolean riskOnly) {
        return credentialListService.getCredentials(issuer, status, riskOnly);
    }
}
