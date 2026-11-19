package com.logssey.reach.ci;

import java.net.URI;
import java.security.Principal;
import java.util.List;

import com.logssey.reach.ci.auth.ReachCiCaller;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ci.dto.ReachCiCheckCreatedResponse;
import com.logssey.reach.ci.dto.ReachCiCheckPageResponse;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach/ci/checks")
public class ReachCiCheckController {
    private final ReachCiCheckService service;

    public ReachCiCheckController(ReachCiCheckService service) {
        this.service = service;
    }

    /**
     * API-12 실행. 202와 Location을 준다. 같은 멱등 키로 다시 보내면 Idempotent-Replayed: true (명세 2-7).
     * 헤더는 required = false로 받아 Service가 400(INVALID_INPUT 본문)을 준다. 스프링 기본 400은 본문이 비어 있다
     */
    @PostMapping
    public ResponseEntity<ReachCiCheckCreatedResponse> create(
            Principal principal,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody ReachCiCheckRequest request) {
        var ci = ReachCiCaller.from(principal);
        var created = ci.isPresent() ? service.createForCi(ci.get(), idempotencyKey, request)
                : service.create(principal == null ? null : principal.getName(), idempotencyKey, request);
        var response = ResponseEntity.accepted().location(URI.create("/api/v1/reach/ci/checks/" + created.check().id()));
        if (created.replayed()) response.header("Idempotent-Replayed", "true");
        return response.body(created.check());
    }

    /**
     * API-12 목록 (대시보드 세션만). CI 토큰은 403: 한 레포의 토큰으로 모든 레포의 검사를 보지 않는다.
     * 쉼표로 준 값은 Spring이 목록으로 나눈다(mode=PR,IMAGE_BUILD)
     */
    @GetMapping
    public ReachCiCheckPageResponse checks(
            Principal principal,
            @RequestParam(required = false) String repository,
            @RequestParam(required = false) List<String> mode,
            @RequestParam(required = false) List<String> scanStatus,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String include) {
        if (ReachCiCaller.from(principal).isPresent()) throw new ApiException(ErrorCode.FORBIDDEN);
        return service.checks(principal == null ? null : principal.getName(),
                new ReachCiCheckFilter(repository, mode, scanStatus), size, cursor, include);
    }

    /**
     * 재대조 입력 SBOM (API-12 보조). 검사가 재대조(rescanOf)면 원래 스캔에 보관한 SBOM을 gzip 그대로 준다.
     * 재대조가 아니거나 보관한 SBOM이 없으면(보관 전 스캔) 404이고, 러너는 이미지에서 SBOM을 다시 만든다
     */
    @GetMapping("/{checkId}/sbom")
    public ResponseEntity<byte[]> sbom(Principal principal, @PathVariable long checkId) {
        var ci = ReachCiCaller.from(principal);
        byte[] gzip = ci.isPresent() ? service.sbomForCi(ci.get(), checkId)
                : service.sbom(principal == null ? null : principal.getName(), checkId);
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/gzip")).body(gzip);
    }

    /**
     * 재대조 입력 L3 실행 기록 (API-12 보조, PRD FR-14). 검사가 재대조면 그 이미지에 보관한 실행 기록을 tar.xz 그대로 준다.
     * 러너는 앱을 다시 띄우지 않고 이 기록을 오늘의 판정 데이터와 다시 대조한다. 없으면 404이고 러너는 L3 없이 올린다
     */
    @GetMapping("/{checkId}/l3-record")
    public ResponseEntity<byte[]> l3Record(Principal principal, @PathVariable long checkId) {
        var ci = ReachCiCaller.from(principal);
        byte[] record = ci.isPresent() ? service.l3RecordForCi(ci.get(), checkId)
                : service.l3Record(principal == null ? null : principal.getName(), checkId);
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/x-xz")).body(record);
    }

    /** API-12 결과 조회 */
    @GetMapping("/{checkId}")
    public ReachCiCheckResponse check(Principal principal, @PathVariable long checkId) {
        var ci = ReachCiCaller.from(principal);
        return ci.isPresent() ? service.checkForCi(ci.get(), checkId)
                : service.check(principal == null ? null : principal.getName(), checkId);
    }
}
