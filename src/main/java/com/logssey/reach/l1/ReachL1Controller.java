package com.logssey.reach.l1;

import java.security.Principal;

import com.logssey.reach.l1.dto.ReachInventoryResponse;

import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachL1Controller {
    private final ReachL1Service service;

    public ReachL1Controller(ReachL1Service service) {
        this.service = service;
    }

    /** L1 수동 업로드 (ADMIN 세션). 수집기 경로 /internal/v1/reach/l1/workloads는 따로 둔다 */
    @PutMapping("/l1/workloads")
    public ReachInventoryResponse upload(Principal principal, @RequestBody ReachInventoryRequest request) {
        return service.upload(principal == null ? null : principal.getName(), request);
    }
}
