package com.logssey.iac.finding;

import java.util.Objects;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** 발견 건(드리프트·조치)의 담당자와 상태를 바꾼다. 바꾼 사람과 전·후 값을 감사 기록에 남긴다 (SR-10). */
@Service
public class IacFindingService {

    private final IacFindingRepository repository;
    private final TransactionTemplate transaction;

    public IacFindingService(IacFindingRepository repository, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public FindingResponse update(long findingId, FindingUpdateRequest request, String loginId) {
        if (request.assigneeUserId() != null && Boolean.TRUE.equals(request.unassign())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return Objects.requireNonNull(transaction.execute(status -> {
            if (loginId == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
            long actor = repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
            var before = repository.lock(findingId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
            if (before.version() != request.version()) {
                throw new ApiException(ErrorCode.CONFLICT, "다른 사용자가 먼저 바꿨습니다. 다시 불러와 주세요.");
            }
            if (request.assigneeUserId() != null && !repository.userExists(request.assigneeUserId())) {
                throw new ApiException(ErrorCode.INVALID_INPUT);
            }
            String newStatus = request.status() == null ? before.status() : request.status();
            Long assignee = Boolean.TRUE.equals(request.unassign()) ? null
                    : request.assigneeUserId() != null ? request.assigneeUserId() : before.assigneeUserId();
            repository.update(findingId, newStatus, assignee);
            var after = new FindingResponse(findingId, newStatus, assignee, before.version() + 1);
            repository.audit(actor, findingId, before, after);
            return after;
        }));
    }
}
