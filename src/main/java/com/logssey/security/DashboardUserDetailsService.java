package com.logssey.security;

import com.logssey.user.DashboardUser;
import com.logssey.user.DashboardUserRepository;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** 로그인할 때 DB의 dashboard_users에서 계정을 찾는다 */
@Service
public class DashboardUserDetailsService implements UserDetailsService {

    private final DashboardUserRepository userRepository;

    public DashboardUserDetailsService(DashboardUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        DashboardUser user = userRepository.findByLoginId(loginId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return User.withUsername(user.getLoginId())
                .password(user.getPasswordHash())
                .roles(user.getRole())
                .build();
    }
}
