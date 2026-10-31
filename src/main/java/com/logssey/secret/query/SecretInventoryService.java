package com.logssey.secret.query;

import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretInventoryService {
    private static final Set<String> ISSUERS = Set.of("ALL", "AWS", "GITHUB", "NOTION", "KUBERNETES");
    private static final Set<String> COMPONENT_STATES = Set.of(
            "ALL", "CONFIRMED", "CANDIDATE", "METADATA_ONLY");
    private final SecretInventoryRepository repository;
    private final SecretAccessService access;

    SecretInventoryService(SecretInventoryRepository repository, SecretAccessService access) {
        this.repository = repository;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public SecretListResponse list(int page, int size, String issuer, String componentState, String loginId) {
        access.requireGlobalRead(access.requirePrincipal(loginId));
        if (page < 0 || page > 1_000_000 || size < 1 || size > 100
                || issuer == null || componentState == null
                || !ISSUERS.contains(issuer) || !COMPONENT_STATES.contains(componentState)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long total = repository.count(issuer, componentState);
        return new SecretListResponse(repository.list(issuer, componentState, size, (long) page * size),
                total, page, size);
    }

    @Transactional(readOnly = true)
    public SecretDetailResponse detail(long id, String loginId) {
        access.requireGlobalRead(access.requirePrincipal(loginId));
        if (id <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        return repository.detail(id).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    @Transactional(readOnly = true)
    public SecretConnectionListResponse connections(String loginId) {
        var principal = access.requirePrincipal(loginId);
        access.requireAnyRole(principal);
        return new SecretConnectionListResponse(repository.connections().stream()
                .filter(connection -> access.hasConnectionRole(principal, connection.connectionId(),
                        com.logssey.secret.access.SecretRole.OPERATIONS)).toList());
    }
}
