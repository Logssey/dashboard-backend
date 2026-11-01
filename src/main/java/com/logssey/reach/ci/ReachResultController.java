package com.logssey.reach.ci;

import java.io.IOException;
import java.security.Principal;

import com.logssey.reach.ci.dto.ReachResultUploadResponse;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach/ci/checks")
public class ReachResultController {
    private final ReachResultService service;

    public ReachResultController(ReachResultService service) {
        this.service = service;
    }

    /**
     * API-13. 본문은 gzip이라 @RequestBody(JSON 변환)를 쓰지 않고 바이트로 읽는다.
     * 한도보다 1바이트만 더 읽어서, 넘었는지는 Service가 보고 413을 준다(큰 본문을 끝까지 메모리에 올리지 않는다)
     */
    @PutMapping("/{checkId}/results")
    public ResponseEntity<ReachResultUploadResponse> upload(
            Principal principal,
            @PathVariable long checkId,
            @RequestHeader(name = "Content-Encoding", required = false) String contentEncoding,
            HttpServletRequest request) throws IOException {
        byte[] body = request.getInputStream().readNBytes(ReachResultService.COMPRESSED_MAX + 1);
        return ResponseEntity.accepted()
                .body(service.upload(principal == null ? null : principal.getName(), checkId, contentEncoding, body));
    }
}
