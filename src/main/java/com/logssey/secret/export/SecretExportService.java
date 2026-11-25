package com.logssey.secret.export;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.query.SecretInventoryFilters;
import com.logssey.secret.query.SecretLocationRepository;
import com.logssey.secret.query.SecretLocationRepository.Row;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import tools.jackson.databind.ObjectMapper;

/**
 * 키·노출 위치 화면과 같은 스냅샷·권한·필터로 열람 가능한 위치만 내보낸다.
 * 1) 화면 목록과 같은 역할 검사(SECURITY 또는 REMEDIATOR)
 * 2) SecretReadSnapshots.require로 스냅샷 소유자·필터·권한 변경 여부를 다시 확인
 * 3) 스냅샷에 저장된 위치를 SecretLocationRepository.visible(위치별 권한 조건)과 한 번 더 교차
 */
@Service
public class SecretExportService {
    static final int KEY_LIMIT = 10_000;
    private static final int PAGE = 500;
    private static final Pattern LINES = Pattern.compile("L([1-9][0-9]{0,8})(?:-L?([1-9][0-9]{0,8}))?");

    private final SecretAccessService access;
    private final SecretReadSnapshots snapshots;
    private final SecretLocationRepository locations;
    private final SecretExportRepository repository;
    private final ObjectMapper json;

    public SecretExportService(SecretAccessService access, SecretReadSnapshots snapshots,
                               SecretLocationRepository locations, SecretExportRepository repository, ObjectMapper json) {
        this.access = access;
        this.snapshots = snapshots;
        this.locations = locations;
        this.repository = repository;
        this.json = json;
    }

    public record ExportFile(String filename, String contentType, byte[] body) { }

    private record Collected(SecretPrincipal actor, SecretExportDocument document) { }

    public ExportFile export(String loginId, String formatCode, SecretInventoryFilters filters, Long runId, String snapshotId) {
        var format = SecretExportFormat.parse(formatCode);
        if (snapshotId == null || snapshotId.isBlank()) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (runId != null && runId <= 0) throw new ApiException(ErrorCode.INVALID_INPUT);
        var collected = snapshots.readConsistently(() -> collect(loginId, filters, runId, snapshotId));
        var document = collected.document();
        Object body = switch (format) {
            case SARIF -> SarifExportWriter.write(document);
            case LOGSSEY_JSON -> LogsseyJsonExportWriter.write(document);
            case GITLEAKS -> GitleaksExportWriter.write(document);
        };
        byte[] bytes = json.writeValueAsBytes(body);
        var changes = new LinkedHashMap<String, Object>();
        changes.put("format", format.code());
        changes.put("keyCount", document.keyCount());
        changes.put("locationCount", document.records().size());
        changes.put("restrictedCoverage", document.restrictedCoverage());
        changes.put("filters", document.filters());
        repository.audit(collected.actor().userId(), json.writeValueAsString(changes));
        return new ExportFile(format.filename(document.generatedAt().toLocalDate()), format.contentType(), bytes);
    }

    private Collected collect(String loginId, SecretInventoryFilters filters, Long runId, String snapshotId) {
        var actor = access.requirePrincipal(loginId);
        access.requireAnyRole(actor);
        // 화면 목록(SecretLocationService.reader)과 같은 기준: OPERATIONS만으로는 키 목록을 볼 수 없다.
        if (!access.hasAnyRole(actor, Set.of(SecretRole.SECURITY, SecretRole.REMEDIATOR)))
            throw new ApiException(ErrorCode.FORBIDDEN);

        var normalized = new TreeMap<>(filters.normalized());
        if (runId != null) normalized.put("runId", runId.toString());
        var header = snapshots.require(snapshotId, actor.userId(), "INVENTORY", normalized,
                snapshots.authorizationRevision(actor.userId()));

        long keyCount = snapshots.count(header, "CredentialSet");
        if (keyCount > KEY_LIMIT)
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE, "한 번에 10,000개까지 내보낼 수 있어요. 조건을 좁혀 주세요.");
        var keys = new LinkedHashMap<Long, Map<String, Object>>();
        for (int page = 0; (long) page * PAGE < keyCount; page++)
            for (var facts : snapshots.page(header, "CredentialSet", page, PAGE))
                keys.put(((Number) facts.get("id")).longValue(), facts);

        var members = repository.memberships(header.snapshotId());
        var base = new SecretInventoryFilters(filters.origin(), "ALL", "ALL", "ALL", "ALL", "ALL", "ALL", "ALL", "ALL");
        var keyOrder = new ArrayList<>(keys.keySet());
        var rows = locations.visible(actor.userId(), null, base).stream()
                .filter(row -> Objects.equals(members.get(row.occurrenceId()), row.secretId()) && keys.containsKey(row.secretId()))
                .sorted(Comparator.comparingInt((Row row) -> keyOrder.indexOf(row.secretId())).thenComparingLong(Row::occurrenceId))
                .toList();

        var records = new ArrayList<SecretExportRecord>();
        for (var row : rows) records.add(record(row, keys.get(row.secretId())));
        var document = new SecretExportDocument(OffsetDateTime.now(ZoneOffset.UTC), header.asOf(),
                header.restrictedCoverage(), safeFilters(normalized), keys.size(), List.copyOf(records));
        return new Collected(actor, document);
    }

    private SecretExportRecord record(Row row, Map<String, Object> key) {
        var evidence = locations.detectionEvidence(row);
        var latest = evidence.isEmpty() ? Map.<String, Object>of() : evidence.getFirst();
        var operational = locations.operationalFacts(row.occurrenceId());
        return new SecretExportRecord(row.secretId(), row.occurrenceId(), row.maskedLabel(), row.issuer(),
                row.credentialType(), Objects.toString(latest.get("ruleId"), "unavailable"),
                Objects.toString(key.get("severity"), "UNASSESSED"),
                Objects.toString(key.get("validationStatus"), "UNCHECKED"),
                row.source(), row.environment(), row.origin(), location(row),
                row.exposure(), Objects.toString(operational.get("exposure_range"), "UNKNOWN"),
                row.presence(), row.actionStatus() == null ? "NO_CASE" : row.actionStatus(),
                row.firstSeenAt(), row.lastSeenAt(), (OffsetDateTime) latest.get("detectedAt"));
    }

    /** 화면 위치 API와 같은 SecretSourceDetails 결과만 쓴다. 확인할 수 없는 좌표는 안전 라벨만 남긴다. */
    private SecretExportRecord.Location location(Row row) {
        var source = locations.sourceDetails(row);
        if (!"AVAILABLE".equals(source.get("status")))
            return new SecretExportRecord.Location("UNAVAILABLE", locations.safeLocationLabel(row),
                    null, null, null, null, null, null, null, null, null);
        Integer start = null, end = null;
        var line = source.get("line");
        if (line != null) {
            var matcher = LINES.matcher(line.toString());
            if (matcher.matches()) {
                start = Integer.valueOf(matcher.group(1));
                end = matcher.group(2) == null ? null : Integer.valueOf(matcher.group(2));
            }
        }
        return new SecretExportRecord.Location(source.get("kind").toString(), str(source.get("label")),
                str(source.get("repository")), str(source.get("branch")), str(source.get("path")), start, end,
                str(source.get("pageId")), str(source.get("blockId")), str(source.get("region")), str(source.get("resource")));
    }

    /** 검색어 원문은 파일·감사 기록에 남기지 않는다. */
    static Map<String, String> safeFilters(Map<String, String> normalized) {
        var result = new TreeMap<String, String>(normalized);
        result.put("hasSearch", Boolean.toString(result.remove("q") != null));
        return result;
    }

    private static String str(Object value) { return value == null ? null : value.toString(); }
}
