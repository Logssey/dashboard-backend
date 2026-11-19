package com.logssey.credential.scan;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** custom_key_patterns 읽기·쓰기. 정규식은 저장하지 않고 읽을 때 KeyRuleCompiler로 다시 만든다 */
@Repository
public class CustomKeyPatternRepository {

    private static final Logger log = LoggerFactory.getLogger(CustomKeyPatternRepository.class);

    /** 등록된 규칙 한 줄 (화면 목록용) */
    public record StoredPattern(long id, String name, String prefix, KeyCharset charset, int length,
                                boolean secret, String createdBy, Instant createdAt) {
    }

    private final JdbcClient jdbcClient;

    public CustomKeyPatternRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public List<StoredPattern> findAll() {
        return jdbcClient.sql("""
                        SELECT pattern_id, name, prefix, charset, key_length, is_secret, created_by, created_at
                        FROM custom_key_patterns
                        ORDER BY pattern_id
                        """)
                .query(CustomKeyPatternRepository::map)
                .list();
    }

    /** 스캐너가 쓸 규칙. 검사를 통과하지 못한 줄은 건너뛰고 경고만 남긴다 (한 줄 때문에 스캔 전체가 멈추지 않게) */
    public List<CustomKeyRule> findAllRules() {
        List<CustomKeyRule> rules = new ArrayList<>();
        for (StoredPattern p : findAll()) {
            try {
                rules.add(KeyRuleCompiler.build(p.id(), p.name(), p.prefix(), p.charset(), p.length(), p.secret()));
            } catch (InvalidKeyRuleException e) {
                log.warn("Skipping invalid custom key pattern. patternId={}", p.id());
            }
        }
        return rules;
    }

    /** 대시보드 관리자(dashboard_users.role = ADMIN)인지. 런타임 예외 정책과 같은 기준 */
    public boolean isAdmin(String loginId) {
        return jdbcClient.sql("""
                        SELECT count(*) FROM dashboard_users
                        WHERE login_id = :loginId AND role = 'ADMIN'
                        """)
                .param("loginId", loginId)
                .query(Long.class)
                .single() > 0;
    }

    public long count() {
        return jdbcClient.sql("SELECT count(*) FROM custom_key_patterns").query(Long.class).single();
    }

    public boolean exists(String prefix, KeyCharset charset, int length) {
        return jdbcClient.sql("""
                        SELECT count(*) FROM custom_key_patterns
                        WHERE prefix = :prefix AND charset = :charset AND key_length = :length
                        """)
                .param("prefix", prefix)
                .param("charset", charset.name())
                .param("length", length)
                .query(Long.class)
                .single() > 0;
    }

    public StoredPattern insert(String name, String prefix, KeyCharset charset, int length, boolean secret, String createdBy) {
        return jdbcClient.sql("""
                        INSERT INTO custom_key_patterns (name, prefix, charset, key_length, is_secret, created_by)
                        VALUES (:name, :prefix, :charset, :length, :secret, :createdBy)
                        RETURNING pattern_id, name, prefix, charset, key_length, is_secret, created_by, created_at
                        """)
                .param("name", name)
                .param("prefix", prefix)
                .param("charset", charset.name())
                .param("length", length)
                .param("secret", secret)
                .param("createdBy", createdBy)
                .query(CustomKeyPatternRepository::map)
                .single();
    }

    /** @return 지웠으면 true. 이미 찾아 둔 키(credentials)는 지우지 않는다 */
    public boolean delete(long id) {
        return jdbcClient.sql("DELETE FROM custom_key_patterns WHERE pattern_id = :id")
                .param("id", id)
                .update() > 0;
    }


    private static StoredPattern map(ResultSet rs, int rowNum) throws SQLException {
        return new StoredPattern(
                rs.getLong("pattern_id"),
                rs.getString("name"),
                rs.getString("prefix"),
                KeyCharset.valueOf(rs.getString("charset")),
                rs.getInt("key_length"),
                rs.getBoolean("is_secret"),
                rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant());
    }
}
