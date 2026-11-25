package com.logssey.compliance;

import java.util.UUID;

import com.logssey.compliance.ComplianceJobDtos.ClaimRequest;
import com.logssey.compliance.ComplianceJobDtos.ClaimedJob;
import com.logssey.compliance.ComplianceJobDtos.CompletionResponse;
import com.logssey.compliance.ComplianceJobDtos.ConnectionCompletionRequest;
import com.logssey.compliance.ComplianceJobDtos.ConnectionCompletionResponse;
import com.logssey.compliance.ComplianceJobDtos.FailureRequest;
import com.logssey.compliance.ComplianceJobDtos.LeaseRequest;
import com.logssey.compliance.ComplianceJobDtos.LeaseResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/internal/v1/compliance/jobs")
public class ComplianceWorkerController {

    private final ComplianceJobService service;

    public ComplianceWorkerController(ComplianceJobService service) {
        this.service = service;
    }

    @PostMapping("/claim")
    public ResponseEntity<ClaimedJob> claim(@RequestBody ClaimRequest request) {
        ClaimedJob claimed = service.claim(request == null ? null : request.workerId());
        return claimed == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(claimed);
    }

    @PostMapping("/{jobId}/heartbeat")
    public LeaseResponse heartbeat(@PathVariable long jobId, @RequestBody LeaseRequest request) {
        return service.heartbeat(jobId, request);
    }

    @PostMapping(value = "/{jobId}/result", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public CompletionResponse result(@PathVariable long jobId,
                                     @RequestParam UUID leaseToken,
                                     @RequestParam long leaseGeneration,
                                     @RequestPart("file") MultipartFile file) {
        return service.complete(jobId, leaseToken, leaseGeneration, file);
    }

    @PostMapping("/{jobId}/connection-completion")
    public ConnectionCompletionResponse completeConnection(@PathVariable long jobId,
                                                            @RequestBody ConnectionCompletionRequest request) {
        return service.completeConnection(jobId, request);
    }

    @PostMapping("/{jobId}/failure")
    public ResponseEntity<Void> failure(@PathVariable long jobId, @RequestBody FailureRequest request) {
        service.fail(jobId, request);
        return ResponseEntity.noContent().build();
    }
}
