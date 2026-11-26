package com.logssey.remediation;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** Reads detector evidence. Never changes a detector verdict or treats a human review as a scan. */
public class ActionVerification {
    public record Result(String status, String message, Long checkId, OffsetDateTime checkedAt,
                         String href, String target, String scope) {}
    public record Candidate(long scanId, String status, OffsetDateTime finishedAt, String target) {}
    private final JdbcTemplate db;
    public ActionVerification(JdbcTemplate db) { this.db = db; }

    public Result read(String kind, long id) {
        var records = db.queryForList("SELECT version, status, updated_at FROM security_action_records WHERE kind=? AND target_id=?", kind, id);
        if (records.isEmpty() || !List.of("AWAITING_CHECK", "RECORDED").contains(records.getFirst().get("status")))
            return pending("수행한 조치를 기록한 뒤 검사 결과를 확인하세요.");
        var record = records.getFirst();
        var actionAt = time(record, "updated_at");
        if (kind.equals("IMAGE")) {
            var scans = db.queryForList("SELECT scan_id FROM security_action_verifications WHERE kind=? AND target_id=? AND action_version=? ORDER BY verification_id DESC LIMIT 1", kind, id, record.get("version"));
            return scans.isEmpty() ? pending("수정한 이미지의 검사 결과를 선택하세요.") : image(id, ((Number) scans.getFirst().get("scan_id")).longValue(), actionAt);
        }
        String sql = kind.equals("IAC_PATH") ? """
            SELECT p.status AS finding_status, j.job_id AS check_id, j.status, j.created_at AS started_at, j.finished_at,
                   'JOB' AS type, '현재 인프라 공격 경로' AS target, NULL::int AS pr_number
            FROM iac_attack_paths p LEFT JOIN iac_jobs j ON j.job_id=p.checked_job_id WHERE p.path_id=?
            """ : """
            SELECT f.status AS finding_status, COALESCE(j.job_id,r.run_id) AS check_id,
                   COALESCE(j.status,r.status) AS status, COALESCE(j.created_at,r.created_at) AS started_at,
                   COALESCE(j.finished_at,r.finished_at) AS finished_at,
                   CASE WHEN j.job_id IS NOT NULL THEN 'JOB' ELSE 'RUN' END AS type,
                   f.resource_address AS target, r.pr_number
            FROM iac_findings f LEFT JOIN iac_jobs j ON j.job_id=f.checked_job_id
            LEFT JOIN iac_runs r ON r.run_id=f.checked_run_id WHERE f.finding_id=?
            """;
        var rows = db.queryForList(sql, id);
        if (rows.isEmpty()) return pending("연결된 검사 결과가 없어요.");
        var row = rows.getFirst();
        if ("ACCEPTED".equals(row.get("finding_status"))) return pending("위험을 수용한 상태예요. 수정으로 해결된 상태는 아니에요.");
        var start = time(row, "started_at"); var end = time(row, "finished_at");
        if (start == null || end == null || start.isBefore(actionAt)) return pending("조치 이후 시작한 검사 결과가 아직 없어요.");
        boolean success = "JOB".equals(row.get("type")) ? "SUCCEEDED".equals(row.get("status")) : "DONE".equals(row.get("status"));
        Long check = ((Number) row.get("check_id")).longValue();
        String href = row.get("pr_number") == null ? "/iac/checks" : "/iac/prs/" + row.get("pr_number");
        String scope = row.get("pr_number") == null ? "연결된 인프라 점검 범위" : "PR 변경 계획 기준 · 운영 반영 여부와 별개";
        boolean newer = "JOB".equals(row.get("type")) ? Boolean.TRUE.equals(db.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM iac_jobs old JOIN iac_jobs n ON n.kind=old.kind
              LEFT JOIN iac_runs ro ON ro.run_id=old.run_id LEFT JOIN iac_runs rn ON rn.run_id=n.run_id
              WHERE old.job_id=? AND (n.created_at,n.job_id)>(old.created_at,old.job_id)
                AND (old.run_id IS NULL OR (rn.repo_id=ro.repo_id AND rn.pr_number IS NOT DISTINCT FROM ro.pr_number)))
            """,Boolean.class,check)) : Boolean.TRUE.equals(db.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM iac_runs old JOIN iac_runs n ON n.repo_id=old.repo_id
              AND n.pr_number IS NOT DISTINCT FROM old.pr_number WHERE old.run_id=?
              AND (n.created_at,n.run_id)>(old.created_at,old.run_id))
            """,Boolean.class,check));
        if (newer) return new Result("UNCONFIRMED","더 최근 검사가 있어요. 해당 검사 완료 후 결과를 확인하세요.",check,end,href,(String)row.get("target"),scope);
        if (!success) return new Result("UNCONFIRMED", "연결된 검사가 성공하지 않아 해소 여부를 확인할 수 없어요.", check, end, href, (String)row.get("target"), scope);
        boolean absent = List.of("CLOSED", "FIXED").contains(row.get("finding_status"));
        return new Result(absent ? "NOT_FOUND" : "FOUND", absent ? "조치 후 검사에서 해당 위험이 발견되지 않았어요." : "조치 후 검사에서도 해당 위험이 발견됐어요.", check, end, href, (String)row.get("target"), scope);
    }

    public List<Candidate> candidates(long findingId) {
        return db.query("""
            SELECT s.scan_id,s.scan_status,s.finished_at,t.image_digest
            FROM reach_findings f JOIN reach_targets original ON original.target_id=f.target_id
            JOIN security_action_records a ON a.kind='IMAGE' AND a.target_id=f.finding_id
            JOIN reach_targets t ON t.target_type='IMAGE' AND original.target_type='IMAGE'
              AND t.image_repository=original.image_repository AND t.app=original.app
            JOIN reach_scans s ON s.target_id=t.target_id
            WHERE f.finding_id=? AND s.trigger_type<>'PR' AND s.created_at>=a.updated_at
            ORDER BY s.created_at DESC,s.scan_id DESC LIMIT 50
            """, (rs,n)->new Candidate(rs.getLong(1),rs.getString(2),rs.getObject(3,OffsetDateTime.class),rs.getString(4)), findingId);
    }

    public Result image(long findingId, long scanId, OffsetDateTime actionAt) {
        var rows = db.queryForList("""
            SELECT s.*, t.image_digest, t.image_repository,
              EXISTS(SELECT 1 FROM reach_sboms b WHERE b.scan_id=s.scan_id) AS has_sbom,
              NOT EXISTS(SELECT 1 FROM unnest(f.sources) tool WHERE NOT jsonb_exists(s.tools, lower(tool))) AS tools_complete,
              EXISTS(SELECT 1 FROM jsonb_array_elements(s.stages) e WHERE e->>'name'='MATCH' AND e->>'status'='SUCCEEDED') AS matched,
              EXISTS(SELECT 1 FROM jsonb_array_elements(s.stages) e WHERE e->>'name'='SBOM' AND e->>'status'='SUCCEEDED') AS sbom_complete,
              EXISTS(SELECT 1 FROM reach_verdicts v JOIN reach_findings found ON found.finding_id=v.finding_id
                WHERE v.scan_id=s.scan_id AND v.method IS DISTINCT FROM 'MANUAL'
                  AND found.vulnerability_id=f.vulnerability_id AND found.component_name=f.component_name AND found.ecosystem=f.ecosystem) AS present,
              EXISTS(SELECT 1 FROM reach_scans newer WHERE newer.target_id=s.target_id AND newer.trigger_type<>'PR'
                AND (newer.created_at,newer.scan_id)>(s.created_at,s.scan_id)) AS outdated
            FROM reach_findings f JOIN reach_targets original ON original.target_id=f.target_id
            JOIN reach_scans s ON s.scan_id=? JOIN reach_targets t ON t.target_id=s.target_id
            WHERE f.finding_id=? AND original.target_type='IMAGE' AND t.target_type='IMAGE'
              AND original.image_repository=t.image_repository AND original.app=t.app AND s.trigger_type<>'PR'
            """, scanId, findingId);
        if (rows.isEmpty()) throw new ApiException(ErrorCode.INVALID_INPUT, "같은 서비스와 이미지 저장소의 검사를 선택하세요.");
        var row = rows.getFirst(); var start = time(row,"started_at");
        if (start == null) start=time(row,"created_at");
        if (actionAt == null || start.isBefore(actionAt) || time(row,"created_at").isBefore(actionAt))
            throw new ApiException(ErrorCode.INVALID_INPUT, "조치 이후 시작한 검사를 선택하세요.");
        String state = "UNCONFIRMED", message = "검사가 완료되지 않았거나 분석 근거가 부족해요.";
        if (Boolean.TRUE.equals(row.get("outdated"))) message="이 이미지에 더 최근 검사가 있어요. 최신 결과를 다시 연결하세요.";
        else if ("SUCCEEDED".equals(row.get("scan_status")) && time(row,"finished_at") != null && Boolean.TRUE.equals(row.get("has_sbom"))
                && Boolean.TRUE.equals(row.get("matched")) && Boolean.TRUE.equals(row.get("sbom_complete")) && Boolean.TRUE.equals(row.get("tools_complete"))) {
            state=Boolean.TRUE.equals(row.get("present")) ? "FOUND" : "NOT_FOUND";
            message=state.equals("FOUND") ? "선택한 이미지 검사에서도 같은 취약점이 발견됐어요." : "선택한 이미지 검사에서 같은 패키지의 해당 취약점이 발견되지 않았어요.";
        }
        return new Result(state,message,scanId,time(row,"finished_at"),"/vulnerabilities/scans?scan="+scanId,
                row.get("image_repository")+"@"+row.get("image_digest"),"선택한 이미지 기준 · 운영 배포 여부는 실행 중 워크로드에서 별도 확인");
    }
    private Result pending(String message) { return new Result("PENDING",message,null,null,null,null,null); }
    static OffsetDateTime time(Map<String,Object> row,String key) {
        Object value=row.get(key); return value instanceof java.sql.Timestamp t ? t.toInstant().atOffset(java.time.ZoneOffset.UTC) : (OffsetDateTime)value;
    }
}
