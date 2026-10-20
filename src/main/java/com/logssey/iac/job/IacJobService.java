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
            repository.audit(actor, jobId, "COLLECT_GRAPH_RECORDED", "status", request.status());
            return new CollectGraphRunResponse(jobId, enrichJobId, stateJobId);
        }));
    }

    /**
     * 지금 점검 (API 계약 POST /jobs/{job}/trigger). 보강·State 점검만 바로 등록한다.
     * 수집은 클러스터의 CronJob 을 Job 으로 띄워야 해서 배포 뒤에, 드리프트는 CI 가 main plan 을 올려야 한다.
     */
    public JobTriggeredResponse trigger(String job, String loginId) {
        String kind = switch (job) {
            case "enrich-graph" -> "ENRICH_GRAPH";
            case "check-state" -> "CHECK_STATE";
            case "collect-graph" -> throw new ApiException(ErrorCode.CONFLICT, "수집은 배포된 클러스터에서만 바로 실행할 수 있습니다.");
            case "check-drift" -> throw new ApiException(ErrorCode.CONFLICT, "드리프트 점검은 main plan 이 올라와야 실행됩니다.");
            default -> throw new ApiException(ErrorCode.NOT_FOUND);
        };
        return Objects.requireNonNull(transaction.execute(status -> {
            long actor = requireAdmin(loginId);
            long jobId = repository.enqueueOnce(kind, "MANUAL", actor);
            repository.audit(actor, jobId, "JOB_TRIGGERED", "kind", kind);
            return new JobTriggeredResponse(jobId, kind);
        }));
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
