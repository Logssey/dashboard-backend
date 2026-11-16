package com.logssey.complianceworker;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class ProwlerCommandTest {

    @Test
    void buildsServiceScopeWithoutAShell() {
        var job = new WorkerDtos.ClaimedJob(7, "prod",
                new WorkerDtos.ScanScope(List.of("ap-northeast-2"), List.of("s3", "iam"), List.of()),
                UUID.randomUUID(), 1, OffsetDateTime.now().plusMinutes(5), "5.46.0");

        assertThat(ProwlerCommand.build("prowler", job, Path.of("/tmp/output"))).containsExactly(
                "prowler", "aws", "--output-formats", "json-ocsf", "--output-directory", "/tmp/output",
                "--output-filename", "result", "--no-banner", "--no-color", "--ignore-exit-code-3",
                "--region", "ap-northeast-2", "--service", "s3", "iam");
    }

    @Test
    void usesChecksInsteadOfServices() {
        var job = new WorkerDtos.ClaimedJob(8, "dev",
                new WorkerDtos.ScanScope(List.of(), List.of(), List.of("s3_bucket_public_access_block")),
                UUID.randomUUID(), 2, OffsetDateTime.now().plusMinutes(5), "5.46.0");

        assertThat(ProwlerCommand.build("prowler", job, Path.of("out")))
                .containsSequence("--check", "s3_bucket_public_access_block")
                .doesNotContain("--service", "--region");
    }
}
