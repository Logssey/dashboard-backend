package com.logssey.iac.job;

import java.util.Map;
import java.util.Objects;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

/**
 * 내부 API (API 계약 POST /jobs/collect-graph/runs).
 * 수집이 끝나면 ENRICH_GRAPH 와 CHECK_STATE 를 등록한다.
 * S3 에서는 로그인한 관리자만 부를 수 있다. CronJob 서비스 계정 토큰(TokenReview) 검증은 S4 에서 붙인다.
 */
@Service
public class IacJobService {

    private final IacJobRepository repository;
    private final TransactionTemplate transaction;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public IacJobService(IacJobRepository repository, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public CollectGraphRunResponse recordCollectGraph(CollectGraphRunRequest request, String loginId) {
        if (request.finishedAt().isBefore(request.startedAt())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String stats = mapper.writeValueAsString(request.stats() == null ? Map.of() : request.stats());
        return Objects.requireNonNull(transaction.execute(status -> {
            long actor = requireAdmin(loginId);
            long jobId = repository.insertCollectGraph(actor, request.status(), request.startedAt(),
                    request.finishedAt(), stats);
            boolean succeeded = "SUCCEEDED".equals(request.status());
            Long enrichJobId = succeeded ? repository.enqueueOnce("ENRICH_GRAPH", actor) : null;
            Long stateJobId = succeeded ? repository.enqueueOnce("CHECK_STATE", actor) : null;
            repository.audit(actor, jobId, "COLLECT_GRAPH_RECORDED", request.status());
            return new CollectGraphRunResponse(jobId, enrichJobId, stateJobId);
        }));
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
