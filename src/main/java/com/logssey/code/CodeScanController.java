package com.logssey.code;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Set;

import com.logssey.code.auth.CodeCiSecurityConfig;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * 코드 취약점(SAST) 결과. 업로드는 서비스 레포 code-scan 워크플로만(CodeCiSecurityConfig), 조회는 대시보드 세션.
 * 화면은 발견 목록만 보여 준다 (조치·상태 관리는 이 파트 범위 밖).
 */
@RestController
@RequestMapping("/api/v1/code")
public class CodeScanController {

    static final int MAX_BODY = 20 * 1024 * 1024;
    private static final Set<String> TOOLS = Set.of("semgrep", "spotbugs");

    private final CodeScanRepository repository;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public CodeScanController(CodeScanRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/scans")
    @ResponseStatus(HttpStatus.CREATED)
    public CodeScanDtos.Uploaded upload(@RequestParam String tool, @RequestParam String commit,
                                        @RequestParam(required = false) String workspace,
                                        HttpServletRequest request, Authentication authentication) throws IOException {
        String repo = CodeCiSecurityConfig.ciRepository(authentication)
                .orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
        if (!TOOLS.contains(tool) || !commit.matches("[0-9a-f]{40}")) throw new ApiException(ErrorCode.INVALID_INPUT);
        byte[] body;
        try (InputStream in = request.getInputStream()) {
            body = in.readNBytes(MAX_BODY + 1);
        }
        if (body.length > MAX_BODY) throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        SarifReader.Result result;
        try {
            result = SarifReader.read(mapper.readTree(body), workspace);
        } catch (JacksonException | IllegalArgumentException e) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long scanId = repository.replace(repo, tool, commit, result);
        return new CodeScanDtos.Uploaded(scanId, result.total(), result.findings().size());
    }

    @GetMapping("/findings")
    public CodeScanDtos.Overview findings() {
        return new CodeScanDtos.Overview(repository.scans(), repository.findings());
    }

    /** 인쇄용 단독 HTML. 브라우저 인쇄 메뉴에서 PDF로 저장한다 */
    @GetMapping(value = "/report", produces = "text/html;charset=UTF-8")
    public ResponseEntity<byte[]> report(Authentication authentication) {
        var document = CodeReportHtml.render(findings(), authentication == null ? null : authentication.getName(),
                OffsetDateTime.now());
        var disposition = ContentDisposition.inline().filename(document.filename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
                .body(document.content());
    }
}
