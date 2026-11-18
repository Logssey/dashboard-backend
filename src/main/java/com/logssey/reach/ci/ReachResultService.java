package com.logssey.reach.ci;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.ci.auth.ReachCiAccess;
import com.logssey.reach.ci.auth.ReachCiCaller;
import com.logssey.reach.ci.dto.ReachResultUploadResponse;
import com.logssey.reach.l1.ReachL1Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Reach 분석 결과 업로드 (API-13). 러너가 올린 묶음을 DB 스키마 4절 순서로 한 트랜잭션에 적재하고 스캔을 끝낸다.
 * 분석은 서버에서 다시 하지 않는다(ARD AD-18). 명세의 인증은 GitHub OIDC지만 아직 붙이지 않아 ADMIN 세션으로 받는다.
 * 명세는 202 뒤에 저장한다고 했지만, 지금은 요청 안에서 저장까지 끝내 끝난 상태(SUCCEEDED·FAILED)를 준다
 */
@Service
public class ReachResultService {

    /** 압축한 본문 한도 (명세 API-13: 20MB, 초안 값). 푼 본문은 따로 막는다(압축 폭탄) */
    static final int COMPRESSED_MAX = 20 * 1024 * 1024;
    static final int UNCOMPRESSED_MAX = 100 * 1024 * 1024;

    private static final List<String> STAGES = List.of("SBOM", "MATCH", "L1", "L2", "REPORT");
    private static final List<String> SOURCES = List.of("TRIVY", "GRYPE");
    private static final List<String> TOOL_METHODS = List.of("CALLGRAPH", "RULE");   // MANUAL은 사람 판정
    private static final List<String> EVIDENCE_KINDS = List.of("FACT", "PATH", "RULE", "NOTE", "RUNTIME");
    /** 근거에서 칸으로 따로 두는 필드. 나머지는 detail에 API 이름 그대로 둔다 (DB 스키마 3-2 reach_evidence) */
    private static final List<String> EVIDENCE_COLUMNS = List.of("order", "kind", "summary", "factId", "ruleId", "informational");
    /** detail 안의 열거값 (명세 3-5). CLI의 소문자를 대문자로 맞춘다 */
    private static final List<String> EVIDENCE_ENUMS = List.of("matchedCondition", "pathTarget", "observationMethod");
    /** MANUAL 판정의 summary 길이. API-06과 같이 메모 앞 500자 (V34 VARCHAR(500)) */
    private static final int SUMMARY_MAX = 500;

    private final ReachResultRepository repository;
    private final ReachL1Service l1;
    private final TransactionTemplate tx;
    private final ReachCiAccess access;
    private final JsonMapper mapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)   // 러너가 칸을 더해도 받는다
            .build();
    /** 근거 해시용. 키 순서를 정렬해 같은 근거면 같은 문자열이 된다 */
    private final JsonMapper canonical = JsonMapper.builder()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build();

    @Autowired
    public ReachResultService(ReachResultRepository repository, ReachL1Service l1, PlatformTransactionManager manager,
                              ReachCiAccess access) {
        this.repository = repository;
        this.l1 = l1;
        this.tx = new TransactionTemplate(manager);
        this.access = access;
    }

    /** CI 설정 없이(CI 토큰은 모두 거부) */
    ReachResultService(ReachResultRepository repository, ReachL1Service l1, PlatformTransactionManager manager) {
        this(repository, l1, manager, ReachCiAccess.closed());
    }

    /** 검사를 마친 Finding 하나. id 칸(대상·스캔·Finding)은 적재하면서 채운다 */
    private record Row(String purl, String vulnerabilityId, String status,
                       ReachResultRepository.FindingInput finding, ReachResultRepository.VerdictInput verdict,
                       List<ReachResultRepository.EvidenceInput> evidence, String proposal) {}

    /** API-13 (대시보드 세션) */
    public ReachResultUploadResponse upload(String loginId, long checkId, String contentEncoding, byte[] body) {
        requireAdmin(loginId);
        return load(checkId, contentEncoding, body);
    }

    /** API-13 (CI 토큰). 검사를 만든 레포의 토큰만 올린다. 본문을 풀기 전에 본다 */
    public ReachResultUploadResponse uploadForCi(ReachCiCaller caller, long checkId, String contentEncoding, byte[] body) {
        access.requireOwner(caller, repository.checkOwner(checkId));
        return load(checkId, contentEncoding, body);
    }

    private ReachResultUploadResponse load(long checkId, String contentEncoding, byte[] body) {
        var bundle = parse(contentEncoding, body);
        var scanRecord = scanRecord(bundle);
        var failure = failure(bundle.failure());
        var rows = failure == null ? rows(bundle) : List.<Row>of();
        var sbom = failure == null ? sbom(bundle.sbom()) : null;
        try {
            return tx.execute(status -> save(checkId, scanRecord, failure, rows, sbom));
        } catch (ApiException e) {
            throw e;
        } catch (RuntimeException e) {
            // 적재가 되돌아갔다. 스캔이 QUEUED·RUNNING에 머물지 않게 실패로 따로 남긴다 (DB 스키마 4절 6단계)
            tx.executeWithoutResult(status -> repository.failAfterError(checkId));
            throw e;
        }
    }

    private ReachResultUploadResponse save(long checkId, ReachResultRepository.ScanRecord scanRecord,
                                           ReachResultBundle.Failure failure, List<Row> rows,
                                           ReachResultRepository.Sbom sbom) {
        var check = repository.lockCheck(checkId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        // 같은 검사에 두 번 올리거나 이미 끝난 스캔이면 409 (명세 API-13: 다시 돌리려면 API-12로 새 검사)
        if (check.uploaded() || !List.of("QUEUED", "RUNNING").contains(check.scanStatus())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        long scanId = check.scanId();
        if (failure != null) {
            repository.failScan(scanId, scanRecord, failure);
            repository.markUploaded(checkId);
            return new ReachResultUploadResponse(checkId, scanId, "FAILED");
        }

        // Finding을 고치기 전에 L1 재계산 잠금을 잡는다. 정기 재계산과 순서를 맞춰야 교착하지 않는다
        l1.lockRecompute();
        repository.startScan(scanId, scanRecord);
        boolean pr = "PR".equals(check.mode());
        for (var row : rows) {
            var shared = pr ? repository.baselineFinding(check.targetId(), row.purl(), row.vulnerabilityId())
                    : Optional.<Long>empty();
            if (shared.isPresent()) {
                // 같은 커밋을 PR로 다시 스캔했다. PR 결과는 이 스캔의 판정으로만 남기고(API-03 counts·게이트가 읽는다)
                // Finding 칸·현재 판정·사람 검토는 기준 스캔의 것을 그대로 둔다 (ARD SR-09)
                long verdictId = repository.insertToolVerdict(row.verdict().withIds(shared.get(), scanId));
                repository.insertEvidence(verdictId, row.evidence());
                continue;
            }
            var upserted = repository.upsertFinding(row.finding().withIds(check.targetId(), scanId));
            long findingId = upserted.id();
            long verdictId = repository.insertToolVerdict(row.verdict().withIds(findingId, scanId));
            repository.insertEvidence(verdictId, row.evidence());
            review(check, scanId, row, findingId, upserted.inserted(), verdictId);
        }
        // 묶음의 deployment는 새 Finding을 만들 때만 쓴다. 이미지 대상은 여기서 L1 조회로 다시 계산한다(PRD FR-04)
        l1.recompute(check.targetId());
        repository.insertSbom(scanId, sbom);   // 재대조(rescanOf)의 입력 (PRD FR-02)
        repository.succeedScan(scanId);
        repository.markUploaded(checkId);
        return new ReachResultUploadResponse(checkId, scanId, "SUCCEEDED");
    }

    /**
     * 검토 처리와 현재 판정 정하기 (DB 스키마 4절 5단계).
     * 1. 새 Finding이면 같은 app·purl·CVE의 가장 최근 다른 Finding에서 사람 판정을 이어받는다(CARRIED). 없으면 검토 전으로 만든다.
     *    PR 검사의 결과는 그 PR의 결과로만 두고 이어받지 않는다 (ARD SR-09)
     * 2. 사람 판정이 남아 있으면 그 검토가 본 도구 판정과 비교해 상태가 다르면 VERDICT_CHANGED, 근거 해시가 다르면 EVIDENCE_CHANGED로 되돌린다(RESET)
     * 3. 사람 판정이 남았고 새 도구 판정이 다시 NOT_ANALYZED면 MANUAL 판정이 현재 판정이다(API-06 예외). 아니면 새 도구 판정이 현재 판정이다
     */
    private void review(ReachResultRepository.CheckState check, long scanId, Row row, long findingId,
                        boolean inserted, long verdictId) {
        if (inserted) {
            var source = "PR".equals(check.mode()) ? Optional.<ReachResultRepository.CarrySource>empty()
                    : repository.carrySource(check.app(), row.purl(), row.vulnerabilityId(), findingId);
            if (source.isEmpty()) {
                repository.insertReview(findingId, verdictId, row.proposal());
                repository.makeCurrent(findingId, verdictId);
                return;
            }
            repository.insertCarriedReview(findingId, source.get());
            repository.insertHistory(findingId, "CARRIED");
        }

        var review = repository.reviewState(findingId);
        boolean human = !"UNREVIEWED".equals(review.reviewState());
        if (human && review.baseStatus() != null) {
            String reason = !review.baseStatus().equals(row.status()) ? "VERDICT_CHANGED"
                    : !Objects.equals(review.baseEvidenceHash(), row.verdict().evidenceHash()) ? "EVIDENCE_CHANGED"
                    : null;
            if (reason != null) {
                repository.resetReview(findingId, reason, verdictId, row.proposal());
                repository.insertHistory(findingId, "RESET");
                human = false;
            }
        }

        if (human && "NOT_ANALYZED".equals(row.status())) {
            if (!repository.currentIsManual(findingId)) {
                long manualId = repository.insertManualVerdict(findingId, scanId, review.status(),
                        summary(review.note()), review.reviewerUserId());
                repository.makeCurrent(findingId, manualId);
            }
            return;   // 이미 MANUAL이 현재 판정이면 그대로 둔다
        }
        repository.makeCurrent(findingId, verdictId);
    }

    /** Content-Encoding: gzip이 필수다(명세 API-13). 한도를 넘으면 413, gzip·JSON이 깨졌으면 400 */
    private ReachResultBundle parse(String contentEncoding, byte[] body) {
        if (!"gzip".equalsIgnoreCase(contentEncoding == null ? null : contentEncoding.trim())) throw invalid();
        if (body == null || body.length == 0) throw invalid();
        if (body.length > COMPRESSED_MAX) throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        byte[] json;
        try (var in = new GZIPInputStream(new ByteArrayInputStream(body))) {
            json = in.readNBytes(UNCOMPRESSED_MAX + 1);
        } catch (IOException e) {
            throw invalid();
        }
        if (json.length > UNCOMPRESSED_MAX) throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        try {
            var bundle = mapper.readValue(json, ReachResultBundle.class);
            if (bundle == null) throw invalid();
            return bundle;
        } catch (JacksonException e) {
            throw invalid();
        }
    }

    /** tools·stages는 늘 필요하다. 실패 묶음이 아니면 sbom·matches·reachResult·verdicts도 필요하다 (명세 API-13 표) */
    private ReachResultRepository.ScanRecord scanRecord(ReachResultBundle b) {
        if (!object(b.tools()) || b.stages() == null || (b.analysis() != null && !b.analysis().isObject())) {
            throw invalid();
        }
        var stages = new ArrayList<JsonNode>();
        for (var stage : b.stages()) {
            if (!(stage instanceof ObjectNode node)) throw invalid();
            var copy = node.deepCopy();
            copy.put("name", upper(text(node, "name"), STAGES));
            copy.put("status", upper(text(node, "status"), ReachCodes.SCAN_STATUSES));
            stages.add(copy);
        }
        if (b.failure() == null
                && (!object(b.sbom()) || !object(b.matches()) || !object(b.reachResult()) || b.verdicts() == null)) {
            throw invalid();
        }
        return new ReachResultRepository.ScanRecord(mapper.writeValueAsString(b.tools()),
                b.analysis() == null ? null : mapper.writeValueAsString(b.analysis()),
                mapper.writeValueAsString(stages));
    }

    /**
     * 보관할 SBOM (PRD FR-02, V53 reach_sboms). 받은 JSON을 다시 직렬화해 gzip으로 둔다.
     * 해시는 푼 JSON의 SHA-256이고, 구성요소 수는 최상위 components 개수다
     */
    private ReachResultRepository.Sbom sbom(JsonNode sbom) {
        byte[] json = mapper.writeValueAsBytes(sbom);
        var out = new ByteArrayOutputStream(json.length / 8 + 64);
        try (var gzip = new GZIPOutputStream(out)) {
            gzip.write(json);
        } catch (IOException e) {
            throw new IllegalStateException(e);   // 메모리 안 스트림이라 나지 않는다
        }
        int components = sbom.path("components").isArray() ? sbom.path("components").size() : 0;
        return new ReachResultRepository.Sbom(out.toByteArray(), sha256(json), components);
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);   // 자바 표준이라 늘 있다
        }
    }

    /** 러너의 실패 사유. code는 E-코드, stage는 단계 이름 (V34 reach_scans 칸 길이) */
    private static ReachResultBundle.Failure failure(ReachResultBundle.Failure f) {
        if (f == null) return null;
        if (blank(f.code()) || f.code().length() > 80 || tooLong(f.message(), 500)) throw invalid();
        return new ReachResultBundle.Failure(f.code(), f.stage() == null ? null : upper(f.stage(), STAGES), f.message());
    }

    /** 항목마다 검사하고 소문자 열거값을 대문자로 맞춘다 (PRD 1절). 같은 purl × CVE가 두 번 나오면 400 */
    private List<Row> rows(ReachResultBundle b) {
        var rows = new ArrayList<Row>();
        var seen = new HashSet<String>();
        for (var item : b.verdicts()) {
            if (item == null || item.component() == null || item.vulnerability() == null || item.verdict() == null) {
                throw invalid();
            }
            var c = item.component();
            var vuln = item.vulnerability();
            if (blank(c.purl()) || !c.purl().startsWith("pkg:") || tooLong(c.purl(), 500) || blank(c.name())
                    || tooLong(c.name(), 200) || blank(c.version()) || tooLong(c.version(), 100) || tooLong(c.path(), 500)
                    || blank(vuln.id()) || tooLong(vuln.id(), 40) || tooLong(vuln.severityNote(), 500)
                    || tooLong(vuln.title(), 500) || tooLong(vuln.affectedFeature(), 500)
                    || hasBlank(vuln.fixedVersions()) || hasBlank(vuln.cwe()) || hasBlank(vuln.references())
                    || (item.upgrade() != null && !item.upgrade().isObject())) {
                throw invalid();
            }
            if (!seen.add(c.purl() + "\n" + vuln.id())) throw invalid();
            // purl 타입 그대로 (pkg:maven/… → maven). 식별자라 대문자로 바꾸지 않는다
            String ecosystem = c.ecosystem() != null ? c.ecosystem()
                    : c.purl().substring(4, Math.max(4, c.purl().indexOf('/')));
            if (blank(ecosystem) || ecosystem.length() > 20) throw invalid();
            if (item.sources() == null || item.sources().isEmpty()) throw invalid();
            var sources = item.sources().stream().map(s -> upper(s, SOURCES)).distinct().toList();
            String deployment = item.deployment() == null ? "UNKNOWN" : upper(item.deployment(), ReachCodes.DEPLOYMENTS);

            var finding = new ReachResultRepository.FindingInput(0, 0, c.purl(), c.name(), c.version(), ecosystem,
                    c.path(), vuln.id(), upper(vuln.severity(), ReachCodes.SEVERITIES), vuln.severityNote(),
                    vuln.title(), vuln.description(), vuln.affectedFeature(), json(vuln.fixedVersions()),
                    json(vuln.cwe()), json(vuln.references()), json(sources), deployment,
                    item.upgrade() == null ? null : mapper.writeValueAsString(item.upgrade()));
            var evidence = evidence(item.verdict());
            var verdict = verdict(item.verdict(), evidence);
            rows.add(new Row(c.purl(), vuln.id(), verdict.status(), finding, verdict, evidence, proposal(item.proposal())));
        }
        return rows;
    }

    /**
     * 도구 판정. NOT_ANALYZED면 방식 없이 사유가 있어야 하고, 아니면 반대다 (V34 CHECK).
     * 근거 없는 UNREACHABLE은 받지 않는다 (ARD 6-4, DB 스키마 4절 4단계)
     */
    private ReachResultRepository.VerdictInput verdict(ReachResultBundle.Verdict v,
                                                      List<ReachResultRepository.EvidenceInput> evidence) {
        String status = upper(v.status(), ReachCodes.STATUSES);
        boolean notAnalyzed = "NOT_ANALYZED".equals(status);
        String method = v.method() == null ? null : upper(v.method(), TOOL_METHODS);
        String reason = v.notAnalyzedReason() == null ? null : upper(v.notAnalyzedReason(), ReachCodes.NOT_ANALYZED_REASONS);
        if (notAnalyzed != (method == null) || notAnalyzed != (reason != null)) throw invalid();
        if (blank(v.summary()) || tooLong(v.summary(), SUMMARY_MAX) || tooLong(v.ruleId(), 80) || !object(v.engine())
                || (v.vulnFunctionIds() != null && v.vulnFunctionIds().contains(null))
                || (v.callgraph() != null && !v.callgraph().isObject())) {
            throw invalid();
        }
        if ("UNREACHABLE".equals(status) && evidence.isEmpty()) throw invalid();
        return new ReachResultRepository.VerdictInput(0, 0, status, method, reason, v.summary(), v.ruleId(),
                json(v.vulnFunctionIds()), v.callgraph() == null ? null : mapper.writeValueAsString(v.callgraph()),
                mapper.writeValueAsString(v.engine()), evidenceHash(v.callgraph(), evidence), v.analyzedAt());
    }

    /** order는 배열 순서로 다시 매긴다(1부터). FACT면 factId, RULE이면 ruleId가 있어야 한다 (V34 CHECK) */
    private List<ReachResultRepository.EvidenceInput> evidence(ReachResultBundle.Verdict v) {
        var result = new ArrayList<ReachResultRepository.EvidenceInput>();
        if (v.evidence() == null) return result;
        for (var item : v.evidence()) {
            if (!(item instanceof ObjectNode node)) throw invalid();
            String kind = upper(text(node, "kind"), EVIDENCE_KINDS);
            String summary = text(node, "summary");
            String factId = text(node, "factId");
            String ruleId = text(node, "ruleId");
            var informational = node.get("informational");
            if (blank(summary) || tooLong(summary, 1000) || tooLong(factId, 120) || tooLong(ruleId, 80)
                    || ("FACT".equals(kind) && blank(factId)) || ("RULE".equals(kind) && blank(ruleId))
                    || (informational != null && !informational.isBoolean())) {
                throw invalid();
            }
            var detail = node.deepCopy();
            detail.remove(EVIDENCE_COLUMNS);
            for (String name : EVIDENCE_ENUMS) {
                var value = detail.get(name);
                if (value != null && value.isString()) detail.put(name, value.stringValue().toUpperCase(Locale.ROOT));
            }
            result.add(new ReachResultRepository.EvidenceInput(result.size() + 1, kind, summary, factId, ruleId,
                    informational != null && informational.booleanValue(), mapper.writeValueAsString(detail)));
        }
        return result;
    }

    /**
     * 근거 해시. 다음 스캔에서 근거가 바뀌었는지(EVIDENCE_CHANGED) 비교하는 값이다.
     * 명세에 없어 정한 것: 근거 목록(칸 + detail)과 callgraph를 키 순서로 정렬한 JSON의 SHA-256. 판정 시각·엔진 버전은 넣지 않는다
     */
    private String evidenceHash(JsonNode callgraph, List<ReachResultRepository.EvidenceInput> evidence) {
        var items = new ArrayList<Map<String, Object>>();
        for (var e : evidence) {
            var item = new LinkedHashMap<String, Object>();
            item.put("kind", e.kind());
            item.put("summary", e.summary());
            item.put("factId", e.factId());
            item.put("ruleId", e.ruleId());
            item.put("informational", e.informational());
            item.put("detail", mapper.readValue(e.detail(), Object.class));
            items.add(item);
        }
        var input = new LinkedHashMap<String, Object>();
        input.put("callgraph", callgraph == null ? null : mapper.convertValue(callgraph, Object.class));
        input.put("evidence", items);
        return ReachCiCheckService.sha256(canonical.writeValueAsString(input));
    }

    /** 새 Finding이나 되돌린 검토에 두는 검토 전 제안 (명세 3-10 proposal) */
    private String proposal(ReachResultBundle.Proposal p) {
        if (p == null) return null;
        if (blank(p.summary())) throw invalid();
        return mapper.writeValueAsString(new ReachResultBundle.Proposal(upper(p.status(), ReachCodes.HUMAN_STATUSES),
                p.summary(), p.reference()));
    }

    /** 대문자로 맞춘 뒤 허용 값인지 본다. 없거나 허용 밖이면 400 */
    private static String upper(String value, List<String> allowed) {
        String upper = value == null ? null : value.toUpperCase(Locale.ROOT);
        if (upper == null || !allowed.contains(upper)) throw invalid();
        return upper;
    }

    private static String text(JsonNode node, String name) {
        var value = node.get(name);
        if (value == null || value.isNull()) return null;
        if (!value.isString()) throw invalid();
        return value.stringValue();
    }

    /** null이면 빈 배열 */
    private String json(List<?> values) {
        return mapper.writeValueAsString(values == null ? List.of() : values);
    }

    private static boolean object(JsonNode node) {
        return node != null && node.isObject();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    /** 문자열 배열 칸(fixedVersions 등)에 null·빈 값이 있는지. 저장하면 배열 안의 NULL이 되어 읽는 쪽이 깨진다 */
    private static boolean hasBlank(List<String> values) {
        return values != null && values.stream().anyMatch(ReachResultService::blank);
    }

    /** DB VARCHAR 길이는 글자(code point) 수다 */
    private static boolean tooLong(String value, int max) {
        return value != null && value.codePointCount(0, value.length()) > max;
    }

    /** API-06과 같은 규칙: MANUAL 판정의 summary는 메모 앞 500자 */
    private static String summary(String note) {
        return !tooLong(note, SUMMARY_MAX) ? note : note.substring(0, note.offsetByCodePoints(0, SUMMARY_MAX));
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }

    private static ApiException invalid() {
        return new ApiException(ErrorCode.INVALID_INPUT);
    }
}
