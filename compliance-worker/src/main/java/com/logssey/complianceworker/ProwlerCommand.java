package com.logssey.complianceworker;

import static com.logssey.complianceworker.WorkerDtos.ClaimedJob;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

final class ProwlerCommand {
    private ProwlerCommand() {}

    static List<String> build(String executable, ClaimedJob job, Path outputDirectory) {
        var args = new ArrayList<>(List.of(
                executable, "aws",
                "--output-formats", "json-ocsf",
                "--output-directory", outputDirectory.toString(),
                "--output-filename", "result",
                "--no-banner", "--no-color", "--ignore-exit-code-3"));
        var scope = job.scope();
        if (scope.regions() != null && !scope.regions().isEmpty()) {
            args.add("--region");
            args.addAll(scope.regions());
        }
        if (scope.services() != null && !scope.services().isEmpty()) {
            args.add("--service");
            args.addAll(scope.services());
        } else if (scope.checks() != null && !scope.checks().isEmpty()) {
            args.add("--check");
            args.addAll(scope.checks());
        }
        return List.copyOf(args);
    }
}
