package com.logssey.compliance;

import java.security.Principal;

import com.logssey.compliance.ComplianceJobDtos.CreateJobRequest;
import com.logssey.compliance.ComplianceJobDtos.CreateJobResponse;
import com.logssey.compliance.ComplianceJobDtos.CancelJobResponse;
import com.logssey.compliance.ComplianceJobDtos.JobListResponse;
import com.logssey.compliance.ComplianceJobDtos.JobSummary;
import com.logssey.compliance.ComplianceJobDtos.ScopeCatalogResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/compliance")
public class ComplianceJobController {

    private final ComplianceJobService service;

    public ComplianceJobController(ComplianceJobService service) {
        this.service = service;
    }

    @GetMapping("/scope-catalog")
    public ScopeCatalogResponse scopeCatalog() {
        return service.scopeCatalog();
    }

    @PostMapping("/jobs")
    public CreateJobResponse create(Principal principal, @RequestBody CreateJobRequest request) {
        return service.create(principal == null ? null : principal.getName(), request);
    }

    @GetMapping("/jobs")
    public JobListResponse jobs(@RequestParam(defaultValue = "20") int limit) {
        return service.jobs(limit);
    }

    @GetMapping("/jobs/{jobId}")
    public JobSummary job(@PathVariable long jobId) {
        return service.job(jobId);
    }

    @PostMapping("/jobs/{jobId}/cancel")
    public CancelJobResponse cancel(Principal principal, @PathVariable long jobId) {
        return service.cancel(principal == null ? null : principal.getName(), jobId);
    }
}
