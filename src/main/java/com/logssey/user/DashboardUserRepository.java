package com.logssey.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DashboardUserRepository extends JpaRepository<DashboardUser, Long> {

    Optional<DashboardUser> findByLoginId(String loginId);

    boolean existsByLoginId(String loginId);
}
