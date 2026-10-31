package com.logssey.reach.review;

import java.security.Principal;

import com.logssey.reach.query.dto.ReachFindingDetailResponse;

import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachReviewController {
    private final ReachReviewService service;

    public ReachReviewController(ReachReviewService service) {
        this.service = service;
    }

    /** API-06. 응답은 바뀐 Review (상세의 review와 같은 모양) */
    @PatchMapping("/findings/{findingId}/review")
    public ReachFindingDetailResponse.Review review(Principal principal,
                                                    @PathVariable long findingId,
                                                    @RequestBody ReachReviewRequest request) {
        return service.save(principal == null ? null : principal.getName(), findingId, request);
    }
}
