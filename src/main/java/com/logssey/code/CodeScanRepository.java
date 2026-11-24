package com.logssey.code;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.IntStream;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class CodeScanRepository {

    private final JdbcTemplate jdbc;

    public CodeScanRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 레포·도구의 이전 검사를 지우고 새 검사로 바꾼다 (V61) */
    @Transactional
    public long replace(String repository, String tool, String commit, SarifReader.Result result) {
        jdbc.update("DELETE FROM code_scans WHERE repository = ? AND tool = ?", repository, tool);
        long scanId = jdbc.queryForObject("""
                INSERT INTO code_scans (repository, tool, commit_sha, total) VALUES (?, ?, ?, ?) RETURNING scan_id
                """, Long.class, repository, tool, commit, result.total());
        List<SarifReader.Finding> findings = result.findings();
        List<Integer> seqs = IntStream.range(0, findings.size()).boxed().toList();
        jdbc.batchUpdate("""
                INSERT INTO code_findings (scan_id, seq, rule_id, severity, cwe, message, path, line, help_uri)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, seqs, 200, (ps, seq) -> {
            SarifReader.Finding finding = findings.get(seq);
            ps.setLong(1, scanId);
            ps.setInt(2, seq);
            ps.setString(3, finding.ruleId());
            ps.setString(4, finding.severity());
            ps.setString(5, finding.cwe());
            ps.setString(6, finding.message());
            ps.setString(7, finding.path());
            ps.setObject(8, finding.line());
            ps.setString(9, finding.helpUri());
        });
        return scanId;
    }

    List<CodeScanDtos.Scan> scans() {
        return jdbc.query("""
                SELECT s.repository, s.tool, s.commit_sha, s.scanned_at, s.total,
                       count(*) FILTER (WHERE f.severity = 'HIGH') AS high,
                       count(*) FILTER (WHERE f.severity = 'MEDIUM') AS medium,
                       count(*) FILTER (WHERE f.severity = 'LOW') AS low
                FROM code_scans s LEFT JOIN code_findings f ON f.scan_id = s.scan_id
                GROUP BY s.scan_id ORDER BY s.repository, s.tool
                """, (rs, row) -> new CodeScanDtos.Scan(rs.getString("repository"), rs.getString("tool"),
                rs.getString("commit_sha"), rs.getObject("scanned_at", OffsetDateTime.class), rs.getInt("total"),
                rs.getInt("high"), rs.getInt("medium"), rs.getInt("low")));
    }

    List<CodeScanDtos.Finding> findings() {
        return jdbc.query("""
                SELECT s.repository, s.tool, s.commit_sha, f.rule_id, f.severity, f.cwe, f.message, f.path, f.line, f.help_uri
                FROM code_findings f JOIN code_scans s ON s.scan_id = f.scan_id
                ORDER BY CASE f.severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,
                         s.repository, f.path, f.line NULLS FIRST, f.seq
                """, (rs, row) -> new CodeScanDtos.Finding(rs.getString("repository"), rs.getString("tool"),
                rs.getString("commit_sha"), rs.getString("rule_id"), rs.getString("severity"), rs.getString("cwe"),
                rs.getString("message"), rs.getString("path"), (Integer) rs.getObject("line"), rs.getString("help_uri")));
    }
}
