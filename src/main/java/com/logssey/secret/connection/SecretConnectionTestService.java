package com.logssey.secret.connection;

import java.time.Clock;
import java.time.OffsetDateTime;
import com.logssey.secret.aws.SecretAwsSourceCredentials;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretRole;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SecretConnectionTestService {

    private final SecretConnectionTestRepository repository;
    private final AwsIdentityProbe aws;
    private final GitHubAuthProbe github;
    private final NotionAuthProbe notion;
    private final Clock clock;
    private final SecretAccessService access;

    @Autowired
    SecretConnectionTestService(SecretConnectionTestRepository repository,
                                AwsIdentityProbe aws, GitHubAuthProbe github, NotionAuthProbe notion,
                                SecretAccessService access) {
        this(repository, aws, github, notion, Clock.systemUTC(), access);
    }

    SecretConnectionTestService(SecretConnectionTestRepository repository,
                                AwsIdentityProbe aws, GitHubAuthProbe github, Clock clock,
                                SecretAccessService access) {
        this(repository, aws, github, null, clock, access);
    }

    SecretConnectionTestService(SecretConnectionTestRepository repository,
                                AwsIdentityProbe aws, GitHubAuthProbe github, NotionAuthProbe notion,
                                Clock clock, SecretAccessService access) {
        this.repository = repository;
        this.aws = aws;
        this.github = github;
        this.notion = notion;
        this.clock = clock;
        this.access = access;
    }

    public SecretConnectionTestResponse test(long id, String loginId) {
        var principal = access.requirePrincipal(loginId);
        access.requireConnectionRole(principal, id, SecretRole.OPERATIONS);
        if (id <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        var connection = repository.connection(id).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!"ACTIVE".equals(connection.status())) throw new ApiException(ErrorCode.CONFLICT);

        ConnectionProbeResult result = switch (connection.provider()) {
            case "AWS" -> testAws(connection);
            case "GITHUB" -> testGitHub(connection);
            case "NOTION" -> testNotion(connection);
            default -> throw new ApiException(ErrorCode.CONFLICT);
        };
        var response = new SecretConnectionTestResponse(id, connection.provider(),
                result.status(), result.reasonCode(), OffsetDateTime.now(clock));
        repository.recordProbe(id, loginId, response);
        return response;
    }

    private ConnectionProbeResult testAws(SecretConnectionTestRepository.Connection connection) {
        if (!SecretAwsSourceCredentials.isReference(connection.authRef())) {
            return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        }
        var summary = repository.awsScopes(connection.id());
        if (summary == null || summary.count() == 0 || summary.invalidCount() != 0
                || summary.accountCount() != 1 || summary.accountId() == null) {
            return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        }
        return SecretAwsSourceCredentials.WORKLOAD_REF.equals(connection.authRef())
                ? aws.probeWorkload(summary.accountId())
                : aws.probe(connection.authRef().substring("aws-profile:".length()), summary.accountId());
    }

    private ConnectionProbeResult testGitHub(SecretConnectionTestRepository.Connection connection) {
        var scope = repository.firstEnabledScope(connection.id());
        if (scope.isEmpty()) return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        return github.probe(scope.orElseThrow());
    }

    private ConnectionProbeResult testNotion(SecretConnectionTestRepository.Connection connection) {
        if (notion == null) throw new ApiException(ErrorCode.CONFLICT);
        var scope = repository.firstEnabledScope(connection.id());
        if (scope.isEmpty()) return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        return notion.probe(scope.orElseThrow());
    }

}
