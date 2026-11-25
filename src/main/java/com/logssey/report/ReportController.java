package com.logssey.report;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reports")
public class ReportController {

    private final ReportService service;

    public ReportController(ReportService service) {
        this.service = service;
    }

    @GetMapping("/options")
    public ReportDtos.Options options(Authentication authentication) {
        return service.options(name(authentication));
    }

    @PostMapping
    public ReportDtos.Created create(@RequestBody ReportDtos.CreateRequest request, Authentication authentication) {
        return service.create(request, name(authentication));
    }

    @GetMapping
    public List<ReportDtos.ListItem> list(Authentication authentication) {
        return service.list(name(authentication));
    }

    @GetMapping("/{reportId}")
    public ReportDtos.Detail get(@PathVariable long reportId, Authentication authentication) {
        return service.get(reportId, name(authentication));
    }

    /** 취약점 한 건의 AI 대응 방법 (이미 있으면 그대로) */
    @PostMapping("/{reportId}/findings/{findingId}/advice")
    public ReportAdvice adviseFinding(@PathVariable long reportId, @PathVariable String findingId,
                                      Authentication authentication) {
        return service.adviseFinding(reportId, findingId, name(authentication));
    }

    @DeleteMapping("/{reportId}")
    public ResponseEntity<Void> delete(@PathVariable long reportId, Authentication authentication) {
        service.delete(reportId, name(authentication));
        return ResponseEntity.noContent().build();
    }

    /** 인쇄용 단독 HTML. 브라우저 인쇄 메뉴에서 PDF로 저장한다 */
    @GetMapping(value = "/{reportId}/print", produces = "text/html;charset=UTF-8")
    public ResponseEntity<byte[]> print(@PathVariable long reportId, Authentication authentication) {
        var document = service.print(reportId, name(authentication));
        var disposition = ContentDisposition.inline().filename(document.filename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
                .body(document.content());
    }

    private static String name(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
