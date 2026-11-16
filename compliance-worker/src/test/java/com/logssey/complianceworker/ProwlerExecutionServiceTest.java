package com.logssey.complianceworker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProwlerExecutionServiceTest {

    @TempDir Path temporary;

    @Test
    void uploadsExactlyOneOcsfFileAndRemovesTemporaryOutput() throws Exception {
        Path executable = executable("success.sh", """
                #!/bin/sh
                set -eu
                output=''
                filename='result'
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --output-directory) output="$2"; shift 2 ;;
                    --output-filename) filename="$2"; shift 2 ;;
                    *) shift ;;
                  esac
                done
                printf '%s' '[{"status_code":"PASS"}]' > "$output/$filename.ocsf.json"
                """);
        var api = mock(ComplianceWorkerApiClient.class);
        var submitted = new AtomicReference<Path>();
        doAnswer(invocation -> { submitted.set(invocation.getArgument(1)); return null; })
                .when(api).submit(eq(job()), any(Path.class));

        new ProwlerExecutionService(properties(executable, Duration.ofSeconds(5)), api).execute(job());

        verify(api).submit(eq(job()), any(Path.class));
        assertThat(submitted.get()).isNotNull();
        assertThat(Files.exists(submitted.get().getParent())).isFalse();
        verifyNoMoreInteractions(api);
    }

    @Test
    void reportsNonZeroExitWithoutUploadingOutput() throws Exception {
        Path executable = executable("failure.sh", "#!/bin/sh\nexit 7\n");
        var api = mock(ComplianceWorkerApiClient.class);

        new ProwlerExecutionService(properties(executable, Duration.ofSeconds(5)), api).execute(job());

        verify(api).fail(job(), "PROWLER_EXIT_FAILURE", true);
        verifyNoMoreInteractions(api);
    }

    @Test
    void terminatesAndRetriesTimedOutScanner() throws Exception {
        Path executable = executable("timeout.sh", "#!/bin/sh\nexec sleep 10\n");
        var api = mock(ComplianceWorkerApiClient.class);

        new ProwlerExecutionService(properties(executable, Duration.ofMillis(100)), api).execute(job());

        verify(api).fail(job(), "PROWLER_TIMEOUT", true);
        verifyNoMoreInteractions(api);
    }

    private ComplianceWorkerProperties properties(Path executable, Duration timeout) {
        return new ComplianceWorkerProperties(true, URI.create("http://127.0.0.1:8080"),
                "01234567890123456789012345678901", "worker-test", Duration.ofSeconds(1),
                Duration.ofSeconds(60), timeout, executable.toString());
    }

    private Path executable(String name, String contents) throws Exception {
        Path path = temporary.resolve(name);
        Files.writeString(path, contents);
        assertThat(path.toFile().setExecutable(true)).isTrue();
        return path;
    }

    private static WorkerDtos.ClaimedJob job() {
        return new WorkerDtos.ClaimedJob(42, "prod",
                new WorkerDtos.ScanScope(List.of("ap-northeast-2"), List.of("s3"), List.of()),
                UUID.fromString("11111111-1111-1111-1111-111111111111"), 3,
                OffsetDateTime.parse("2026-11-16T12:00:00Z"), "5.46.0");
    }
}
