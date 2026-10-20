package com.logssey.iac.finding;

import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/iac/findings")
public class IacFindingController {

    private final IacFindingService service;

    public IacFindingController(IacFindingService service) {
        this.service = service;
    }

    @PatchMapping("/{findingId}")
    public FindingResponse update(@PathVariable long findingId, @Valid @RequestBody FindingUpdateRequest request,
                                  Authentication authentication) {
        return service.update(findingId, request, authentication == null ? null : authentication.getName());
    }
}
