package com.logssey.user;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** 대시보드 사용자 (ERD: dashboard_users). 이번 단계는 관리자 1명만 존재한다. */
@Entity
@Table(name = "dashboard_users")
public class DashboardUser {

    public static final String ROLE_ADMIN = "ADMIN";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "login_id", nullable = false, length = 50, unique = true)
    private String loginId;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "display_name", nullable = false, length = 50)
    private String displayName;

    @Column(name = "role", nullable = false, length = 10)
    private String role;

    // DB 기본값(now())으로 채워진다
    @Column(name = "created_at", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz")
    private Instant createdAt;

    @Column(name = "last_login_at", columnDefinition = "timestamptz")
    private Instant lastLoginAt;

    protected DashboardUser() {
    }

    private DashboardUser(String loginId, String passwordHash, String displayName, String role) {
        this.loginId = loginId;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.role = role;
    }

    public static DashboardUser createAdmin(String loginId, String passwordHash, String displayName) {
        return new DashboardUser(loginId, passwordHash, displayName, ROLE_ADMIN);
    }

    public void recordLogin(Instant loggedInAt) {
        this.lastLoginAt = loggedInAt;
    }

    public Long getUserId() { return userId; }
    public String getLoginId() { return loginId; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName() { return displayName; }
    public String getRole() { return role; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastLoginAt() { return lastLoginAt; }
}
