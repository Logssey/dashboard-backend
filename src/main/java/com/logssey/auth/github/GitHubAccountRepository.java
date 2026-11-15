package com.logssey.auth.github;

import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** GitHub로 들어온 사람의 dashboard_users 계정 (ADR-D010) */
@Repository
class GitHubAccountRepository {

    /**
     * GitHub 계정의 password_hash. BCrypt 형식이 아니라서 비밀번호 로그인은 항상 불일치로 끝난다.
     * password_hash 의 NOT NULL 을 유지하면서 GitHub 계정에 비밀번호 로그인을 막는다.
     */
    static final String NO_PASSWORD = "!github-login";

    private final JdbcClient jdbcClient;

    GitHubAccountRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    Optional<Account> findByGithubId(long githubId) {
        return jdbcClient.sql("""
                        SELECT user_id, login_id, role, github_id
                        FROM dashboard_users
                        WHERE github_id = :githubId
                        """)
                .param("githubId", githubId)
                .query(Account.class)
                .optional();
    }

    Optional<Account> findByLoginId(String loginId) {
        return jdbcClient.sql("""
                        SELECT user_id, login_id, role, github_id
                        FROM dashboard_users
                        WHERE login_id = :loginId
                        """)
                .param("loginId", loginId)
                .query(Account.class)
                .optional();
    }

    Account create(String loginId, long githubId, String displayName) {
        return jdbcClient.sql("""
                        INSERT INTO dashboard_users (login_id, password_hash, display_name, role, github_id, last_login_at)
                        VALUES (:loginId, :passwordHash, :displayName, 'ADMIN', :githubId, now())
                        RETURNING user_id, login_id, role, github_id
                        """)
                .param("loginId", loginId)
                .param("passwordHash", NO_PASSWORD)
                .param("displayName", displayName)
                .param("githubId", githubId)
                .query(Account.class)
                .single();
    }

    /** GitHub 이름이 바뀌었으면 login_id 도 따라 바꾸고, 마지막 로그인 시각을 남긴다 */
    void recordLogin(long userId, String loginId) {
        jdbcClient.sql("""
                        UPDATE dashboard_users
                        SET login_id = :loginId, last_login_at = now()
                        WHERE user_id = :userId
                        """)
                .param("loginId", loginId)
                .param("userId", userId)
                .update();
    }

    record Account(long userId, String loginId, String role, Long githubId) {
    }
}
