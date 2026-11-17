package com.logssey.compliance;

import java.security.Principal;
import java.nio.charset.StandardCharsets;

import com.logssey.compliance.ComplianceDtos.CatalogResponse;
import com.logssey.compliance.ComplianceDtos.ImportResponse;
import com.logssey.compliance.ComplianceDtos.OverviewResponse;
import com.logssey.compliance.ComplianceDtos.RunDetailResponse;
import com.logssey.compliance.ComplianceDtos.RunListResponse;

import org.springframework.http.MediaType;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/compliance")
public class ComplianceController {

    private final ComplianceService service;
    private final ComplianceReportService reports;

    public ComplianceController(ComplianceService service, ComplianceReportService reports) {
        this.service = service;
        this.reports = reports;
    }

    @GetMapping("/overview")
    public OverviewResponse overview(@RequestParam(required = false) String targetKey,
                                     @RequestParam(defaultValue = "ALL") String environment) {
        return service.overview(targetKey, environment);
    }

    @GetMapping("/runs")
    public RunListResponse runs(@RequestParam(required = false) String targetKey,
                                @RequestParam(defaultValue = "ALL") String environment,
                                @RequestParam(defaultValue = "20") int limit) {
        return service.runs(targetKey, environment, limit);
    }

    @GetMapping("/runs/{runId}")
    public RunDetailResponse run(@PathVariable long runId, @RequestParam(required = false) String targetKey) {
        return service.run(targetKey, runId);
    }

    @GetMapping(value = "/runs/{runId}/report", produces = "text/html;charset=UTF-8")
    public ResponseEntity<byte[]> report(@PathVariable long runId,
                                         @RequestParam(required = false) String targetKey,
                                         @RequestParam(defaultValue = "all") String framework) {
        var report = reports.report(targetKey, runId, framework);
        var disposition = ContentDisposition.inline()
                .filename(report.filename(), StandardCharsets.UTF_8)
                .build();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
                .body(report.content());
    }

    @GetMapping("/catalog")
    public CatalogResponse catalog() {
        return service.catalog();
    }

    @PostMapping(value = "/imports", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ImportResponse importProwler(Principal principal,
                                        @RequestParam(required = false) String targetKey,
                                        @RequestParam(defaultValue = "prod") String environment,
                                        @RequestPart("file") MultipartFile file) {
        return service.importProwler(principal == null ? null : principal.getName(), targetKey, environment, file);
    }
}
