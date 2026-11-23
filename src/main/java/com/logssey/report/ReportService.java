package com.logssey.report;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 파트 리포트 만들기·목록·보기·인쇄·삭제. 모두 ADMIN 세션.
 * 파트를 여러 개 고르면 파트마다 리포트를 하나씩 만든다. 장을 아직 제공하지 않는 파트는 "데이터 연결 전" 리포트가 된다.
 */
@Service
public class ReportService {

    static final ZoneId KST = ZoneId.of("Asia/Seoul");
    static final int MAX_PERIOD_DAYS = 366;
    static final int LIST_LIMIT = 50;

    private static final Logger log = LoggerFactory.getLogger(ReportService.class);

    private final ReportRepository repository;
    private final ReportAdvisor advisor;
    private final TransactionTemplate transaction;
    private final Map<ReportPart, ReportChapterProvider> providers = new EnumMap<>(ReportPart.class);

    public ReportService(ReportRepository repository, List<ReportChapterProvider> providers, ReportAdvisor advisor,
                         PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.advisor = advisor;
        this.transaction = new TransactionTemplate(transactionManager);
        providers.forEach(p -> this.providers.put(p.part(), p));
    }

    public ReportDtos.Options options(String loginId) {
        requireAdmin(loginId);
        return new ReportDtos.Options(List.copyOf(providers.keySet()), advisor.enabled());
    }

    /** AI 호출이 길 수 있어 트랜잭션 밖에서 만들고, 저장만 짧은 트랜잭션으로 한다 */
    public ReportDtos.Created create(ReportDtos.CreateRequest request, String loginId) {
        var admin = requireAdmin(loginId);
        var parts = parts(request);
        LocalDate from = request.periodFrom(), to = request.periodTo();
        if (from == null || to == null || from.isAfter(to) || to.isAfter(LocalDate.now(KST))
                || ChronoUnit.DAYS.between(from, to) >= MAX_PERIOD_DAYS) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String custom = request.name() == null ? "" : request.name().strip();
        if (custom.length() > 100) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }

        OffsetDateTime now = OffsetDateTime.now(KST).truncatedTo(ChronoUnit.SECONDS);
        OffsetDateTime periodStart = from.atStartOfDay(KST).toOffsetDateTime();
        OffsetDateTime periodEnd = to.plusDays(1).atStartOfDay(KST).toOffsetDateTime();
        List<ReportContent> contents = new ArrayList<>();
        for (ReportPart part : parts) {
            var provider = providers.get(part);
            ReportChapter chapter;
            try {
                chapter = provider == null ? ReportChapter.notConnected(part) : provider.chapter(periodStart, periodEnd, loginId);
            } catch (ApiException e) {
                throw e;
            } catch (RuntimeException e) {
                // 원인은 로그로만 남긴다 (식별자가 섞일 수 있어 응답에 쓰지 않는다)
                log.warn("report chapter failed: part={}", part, e);
                throw new ApiException(ErrorCode.INTERNAL_ERROR);
            }
            // 데이터가 없는 파트는 AI 에 보내지 않는다
            var advice = provider == null
                    ? ReportAdvice.notGenerated(ReportAdvice.DISABLED, "PART_NOT_CONNECTED", null, request.aiRequest())
                    : advisor.advise(chapter, request.aiRequest());
            String name = custom.isEmpty() ? "[" + part.label() + "] 보안 리포트 " + from + " ~ " + to
                    : (parts.size() > 1 ? "[" + part.label() + "] " + custom : custom);
            contents.add(ReportComposer.compose(name, from, to, now, admin.displayName(), chapter, advice, provider != null));
        }
        List<Long> ids = transaction.execute(status -> contents.stream().map(content -> {
            long id = repository.insert(content, admin.userId());
            repository.audit(id, admin.userId(), "CREATED");
            return id;
        }).toList());
        return new ReportDtos.Created(ids);
    }

    /** 이 건을 해결하는 공통 조치만. 하나도 없으면 전부 */
    static List<ReportChapter.Remediation> relatedActions(ReportFinding finding, List<ReportContent.Action> actions) {
        var related = actions.stream().filter(a -> a.findingIds().contains(finding.id())).toList();
        return (related.isEmpty() ? actions : related).stream()
                .map(a -> new ReportChapter.Remediation(a.title(), a.how(), a.impact(), a.link())).toList();
    }

    private List<ReportPart> parts(ReportDtos.CreateRequest request) {
        if (request.parts() == null || request.parts().isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var selected = new LinkedHashSet<ReportPart>();
        for (String name : request.parts()) {
            try {
                selected.add(ReportPart.valueOf(name));
            } catch (IllegalArgumentException | NullPointerException e) {
                throw new ApiException(ErrorCode.INVALID_INPUT);
            }
        }
        return selected.stream().sorted().toList();
    }

    public List<ReportDtos.ListItem> list(String loginId) {
        requireAdmin(loginId);
        return repository.latest(LIST_LIMIT).stream().map(row -> new ReportDtos.ListItem(row.reportId(), row.part(),
                row.name(), row.periodFrom(), row.periodTo(),
                row.content().vulnerabilities().severityCounts().getOrDefault("CRITICAL", 0L),
                row.content().vulnerabilities().overdue(), row.content().overview().connected(), row.createdAt(),
                row.content().createdBy())).toList();
    }

    public ReportDtos.Detail get(long reportId, String loginId) {
        var admin = requireAdmin(loginId);
        var row = repository.find(reportId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        repository.audit(reportId, admin.userId(), "VIEWED");
        return new ReportDtos.Detail(reportId, row.content(), repository.findingAdvice(reportId));
    }

    /**
     * 취약점 한 건의 AI 대응 방법. 이미 만든 것이 있으면 그대로 돌려주고, 없으면 만들어 리포트에 붙인다.
     * 리포트에 실린 값(스냅샷)만 보낸다. 실패한 결과는 저장하지 않아 다시 누를 수 있다.
     */
    public ReportAdvice adviseFinding(long reportId, String findingId, String loginId) {
        var admin = requireAdmin(loginId);
        var row = repository.find(reportId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        var existing = repository.findingAdvice(reportId).get(findingId);
        if (existing != null) {
            return existing;
        }
        var finding = row.content().vulnerabilities().findings().stream()
                .filter(f -> f.id().equals(findingId)).findFirst()
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        var advice = advisor.adviseFinding(row.part(), finding, relatedActions(finding, row.content().remediation().actions()),
                row.content().remediation().advice().request());
        if (ReportAdvice.GENERATED.equals(advice.status())) {
            repository.saveFindingAdvice(reportId, findingId, advice, admin.userId());
            return repository.findingAdvice(reportId).get(findingId);
        }
        return advice;
    }

    public ReportHtmlRenderer.Document print(long reportId, String loginId) {
        var admin = requireAdmin(loginId);
        var row = repository.find(reportId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        repository.audit(reportId, admin.userId(), "PRINTED");
        return ReportHtmlRenderer.render(reportId, row.content(), repository.findingAdvice(reportId));
    }

    /** 목록에서 숨긴다. 본문은 비우고 삭제 기록을 남긴다 */
    public void delete(long reportId, String loginId) {
        var admin = requireAdmin(loginId);
        transaction.executeWithoutResult(status -> {
            if (!repository.softDelete(reportId, admin.userId())) {
                throw new ApiException(ErrorCode.NOT_FOUND);
            }
            repository.audit(reportId, admin.userId(), "DELETED");
        });
    }

    private ReportRepository.Admin requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.admin(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
