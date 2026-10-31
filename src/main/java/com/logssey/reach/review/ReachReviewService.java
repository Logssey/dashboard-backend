package com.logssey.reach.review;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 사람 검토 기록 (API-06). 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional   // 쓰기라 readOnly가 아니다. 안의 쿼리가 한 트랜잭션이라 중간에 실패하면 전부 되돌아간다
public class ReachReviewService {

    /** 메모 길이 (API 명세 API-06, V34 VARCHAR(2000)) */
    private static final int NOTE_MAX = 2000;
    /** MANUAL 판정의 summary 길이 (V34 VARCHAR(500)) */
    private static final int SUMMARY_MAX = 500;

    private final ReachReviewRepository repository;

    public ReachReviewService(ReachReviewRepository repository) {
        this.repository = repository;
    }

    /** API-06 */
    public ReachFindingDetailResponse.Review save(String loginId, long findingId, ReachReviewRequest request) {
        long userId = requireAdmin(loginId);
        validate(request);
        var state = repository.lockReview(findingId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (state.version() != request.version()) throw new ApiException(ErrorCode.CONFLICT);

        // 도구가 판정하지 않은 Finding만 사람 판정이 현재 판정이 된다 (API 명세 API-06 예외)
        var tool = repository.latestToolVerdict(findingId);
        if ("NOT_ANALYZED".equals(tool.status())) {
            if (request.status() != null) {
                repository.turnOffCurrentVerdict(findingId);
                repository.insertManualVerdict(findingId, state.lastScanId(), request.status(),
                        summary(request.note()), userId);
            } else if ("MANUAL".equals(state.currentMethod())) {
                // UNREVIEWED로 되돌리면 도구의 원래 판정으로 돌아간다. MANUAL 행은 판정 이력으로 남는다
                repository.turnOffCurrentVerdict(findingId);
                repository.turnOnVerdict(tool.id());
            }
        }

        if (repository.updateReview(findingId, request, userId, tool.id()) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.insertHistory(findingId);
        return repository.review(findingId);
    }

    /** 사람 판정(확정·잠정)에는 판정과 근거 메모가 있어야 하고(NFR-02), 제안은 검토 전에만 받는다 */
    private static void validate(ReachReviewRequest request) {
        if (request.version() == null || !in(request.reviewState(), ReachCodes.REVIEW_STATES)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if ("UNREVIEWED".equals(request.reviewState())) {
            var proposal = request.proposal();
            if (request.status() != null || request.note() != null
                    || (proposal != null && (!in(proposal.status(), ReachCodes.HUMAN_STATUSES) || blank(proposal.summary())))) {
                throw new ApiException(ErrorCode.INVALID_INPUT);
            }
            return;
        }
        if (!in(request.status(), ReachCodes.HUMAN_STATUSES) || blank(request.note())
                || length(request.note()) > NOTE_MAX || request.proposal() != null) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }

    /** List.of(...).contains(null)은 NullPointerException이라 null을 먼저 거른다 */
    private static boolean in(String value, List<String> allowed) {
        return value != null && allowed.contains(value);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    /** DB VARCHAR 길이는 글자(code point) 수라 Java length()(UTF-16 단위)와 다르다. 이모지는 length()로 2다 */
    private static int length(String value) {
        return value.codePointCount(0, value.length());
    }

    /** 명세에 없어 정한 것: MANUAL 판정의 summary는 메모 앞 500자 */
    private static String summary(String note) {
        return length(note) <= SUMMARY_MAX ? note : note.substring(0, note.offsetByCodePoints(0, SUMMARY_MAX));
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
