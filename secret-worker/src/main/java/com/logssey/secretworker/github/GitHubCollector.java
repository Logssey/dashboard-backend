package com.logssey.secretworker.github;

import tools.jackson.databind.JsonNode;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reads approved source content at a pinned commit and hands each text blob to a synchronous
 * consumer.
 */
public final class GitHubCollector {
    private static final Pattern SHA = Pattern.compile("[0-9a-fA-F]{40,64}");
    private final GitHubRestClient api;
    private final GitHubAppTokenProvider tokens;

    public GitHubCollector(GitHubRestClient api, GitHubAppTokenProvider tokens) {
        this.api = Objects.requireNonNull(api);
        this.tokens = Objects.requireNonNull(tokens);
    }

    public GitHubCollector observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) {
        return new GitHubCollector(api.observed(observer), tokens.observed(observer));
    }

    /**
     * The sink must consume bytes before returning. The collector zeroes its buffer immediately
     * afterwards.
     */
    @FunctionalInterface
    public interface ContentSink {
        void accept(Source source, byte[] utf8Content);
    }

    public enum Status { SUCCEEDED, PARTIAL, FAILED }

    public enum GapCode {
        PATH_NOT_FOUND, ACCESS_DENIED, RATE_LIMITED, SOURCE_UNAVAILABLE, API_ERROR,
        MALFORMED_RESPONSE, TREE_TRUNCATED, TREE_LIMIT, FILE_LIMIT, FILE_TOO_LARGE,
        TOTAL_BYTES_LIMIT, BINARY_FILE, GIT_LFS_POINTER, UNSUPPORTED_OBJECT, DEPTH_LIMIT,
        CONSUMER_FAILED
    }

    public record Source(String owner, String repository, String branch, String commitSha,
                         String path, String blobSha, long size) { }

    public record Gap(String path, GapCode code) { }

    /**
     * Contains metadata only. In particular it never contains a blob, token, or provider error
     * body.
     */
    public record Result(Status status, String commitSha, int objectCount, long byteCount,
                         List<Source> objects, List<Gap> gaps) {
        @Override public String toString() {
            return "GitHubCollectionResult[status=" + status + ", objectCount=" + objectCount
                    + ", byteCount=" + byteCount + ", gapCount=" + gaps.size() + "]";
        }
    }

    public record RepositoryAccess(
            boolean publicRepository,
            boolean metadataComplete,
            java.time.OffsetDateTime observedAt,
            String reasonCode) {}

    /**
     * Collection credentials fetch repository metadata; they never authenticate a discovered PAT.
     */
    public RepositoryAccess repositoryAccess(GitHubApprovedScope scope) {
        try {
            var metadata =
                    api.get(
                            "repos/"
                                    + GitHubRestClient.encodeSegment(scope.owner())
                                    + "/"
                                    + GitHubRestClient.encodeSegment(scope.repository()),
                            tokens.tokenFor(scope),
                            65_536);
            return classifyRepositoryAccess(
                    metadata, java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC));
        } catch (RuntimeException ignored) {
            return new RepositoryAccess(
                    false,
                    false,
                    java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
                    "METADATA_UNAVAILABLE");
        }
    }

    static RepositoryAccess classifyRepositoryAccess(
            JsonNode metadata, java.time.OffsetDateTime at) {
        if (metadata == null || !metadata.isObject())
            return new RepositoryAccess(false, false, at, "METADATA_INCOMPLETE");
        var privateNode = metadata.path("private");
        var visibilityNode = metadata.path("visibility");
        boolean hasPrivate = !privateNode.isMissingNode();
        boolean hasVisibility = !visibilityNode.isMissingNode();
        boolean privateValid = privateNode.isBoolean();
        boolean visibilityValid =
                visibilityNode.isTextual()
                        && Set.of("public", "private", "internal")
                                .contains(visibilityNode.asText(""));
        if (hasPrivate && !privateValid
                || hasVisibility && !visibilityValid
                || !hasPrivate && !hasVisibility)
            return new RepositoryAccess(false, false, at, "METADATA_INCOMPLETE");
        Boolean byPrivate = privateValid ? !privateNode.asBoolean() : null;
        Boolean byVisibility = visibilityValid ? "public".equals(visibilityNode.asText("")) : null;
        if (byPrivate != null && byVisibility != null && !byPrivate.equals(byVisibility))
            return new RepositoryAccess(false, false, at, "METADATA_CONFLICT");
        boolean isPublic = byPrivate != null ? byPrivate : Boolean.TRUE.equals(byVisibility);
        return new RepositoryAccess(
                isPublic, true, at, isPublic ? "PUBLIC_CONFIRMED" : "REPOSITORY_NON_PUBLIC");
    }

    public Result collect(GitHubApprovedScope scope, GitHubCollectionLimits limits, ContentSink sink) {
        Objects.requireNonNull(scope);
        Objects.requireNonNull(limits);
        Objects.requireNonNull(sink);
        State state = new State(scope, limits, sink);
        try {
            String token = tokens.tokenFor(scope);
            String base = "repos/" + GitHubRestClient.encodeSegment(scope.owner()) + "/"
                    + GitHubRestClient.encodeSegment(scope.repository()) + "/git/";
            String branchPath =
                    Arrays.stream(scope.branch().split("/"))
                            .map(GitHubRestClient::encodeSegment)
                            .reduce((a, b) -> a + "/" + b)
                            .orElseThrow();
            JsonNode ref = api.get(base + "ref/heads/" + branchPath, token, limits.maxJsonBytes());
            String commitSha = checkedSha(ref.path("object").path("sha"));
            if (!"commit".equals(ref.path("object").path("type").asText(""))) {
                throw malformed();
            }
            state.commitSha = commitSha;
            JsonNode commit = api.get(base + "commits/" + commitSha, token, limits.maxJsonBytes());
            String rootTreeSha = checkedSha(commit.path("tree").path("sha"));
            String prefixTreeSha = resolvePrefix(base, token, rootTreeSha, state);
            if (prefixTreeSha == null) {
                state.gaps.add(new Gap(scope.pathPrefix(), GapCode.PATH_NOT_FOUND));
                return state.result();
            }
            collectTree(base, token, prefixTreeSha, state);
        } catch (GitHubSourceException error) {
            state.gaps.add(new Gap(scope.pathPrefix(), map(error)));
        } catch (IncompleteTreeException error) {
            state.gaps.add(new Gap(scope.pathPrefix(), error.code));
        } catch (MalformedSourceException error) {
            state.gaps.add(new Gap(scope.pathPrefix(), GapCode.MALFORMED_RESPONSE));
        }
        return state.result();
    }

    /**
     * Reacquires exactly one currently approved file. Historical blob IDs never authorize a read.
     */
    public Result collectFile(
            GitHubApprovedScope scope,
            String path,
            GitHubCollectionLimits limits,
            ContentSink sink) {
        if (path == null
                || !path.startsWith(scope.pathPrefix())
                || path.endsWith("/")
                || Arrays.stream(path.split("/", -1))
                        .anyMatch(
                                p ->
                                        p.isBlank()
                                                || p.equals(".")
                                                || p.equals("..")
                                                || p.indexOf('\\') >= 0))
            throw new IllegalArgumentException("INVALID_TARGET_FILE");
        State state = new State(scope, limits, sink);
        try {
            String token = tokens.tokenFor(scope),
                    base =
                            "repos/"
                                    + GitHubRestClient.encodeSegment(scope.owner())
                                    + "/"
                                    + GitHubRestClient.encodeSegment(scope.repository())
                                    + "/git/";
            String branch =
                    Arrays.stream(scope.branch().split("/"))
                            .map(GitHubRestClient::encodeSegment)
                            .reduce((a, b) -> a + "/" + b)
                            .orElseThrow();
            var ref = api.get(base + "ref/heads/" + branch, token, limits.maxJsonBytes());
            if (!"commit".equals(ref.path("object").path("type").asText(""))) throw malformed();
            state.commitSha = checkedSha(ref.path("object").path("sha"));
            String tree =
                    checkedSha(
                            api.get(
                                            base + "commits/" + state.commitSha,
                                            token,
                                            limits.maxJsonBytes())
                                    .path("tree")
                                    .path("sha"));
            String[] segments = path.split("/");
            JsonNode found = null;
            for (int i = 0; i < segments.length; i++) {
                found = null;
                for (var entry : loadTree(base, token, tree, state))
                    if (segments[i].equals(entry.path("path").asText(""))) {
                        found = entry;
                        break;
                    }
                if (found == null) {
                    state.gaps.add(new Gap(path, GapCode.PATH_NOT_FOUND));
                    return state.result();
                }
                if (i < segments.length - 1) {
                    if (!"tree".equals(found.path("type").asText(""))) throw malformed();
                    tree = checkedSha(found.path("sha"));
                }
            }
            if (found == null
                    || !"blob".equals(found.path("type").asText(""))
                    || !Set.of("100644", "100755").contains(found.path("mode").asText("")))
                throw malformed();
            String sha = checkedSha(found.path("sha"));
            long size = found.path("size").asLong(-1);
            if (size < 0 || size > limits.maxFileBytes()) {
                state.gaps.add(new Gap(path, GapCode.FILE_TOO_LARGE));
                return state.result();
            }
            JsonNode blob = api.get(base + "blobs/" + sha, token, limits.maxJsonBytes());
            if (!"base64".equals(blob.path("encoding").asText(""))) throw malformed();
            byte[] bytes = Base64.getMimeDecoder().decode(blob.path("content").asText(""));
            try {
                if (bytes.length != size || bytes.length > limits.maxFileBytes()) throw malformed();
                // Reuse the same strict UTF-8/binary check as the full collector.
                if (isBinary(bytes)) throw malformed();
                Source source =
                        new Source(
                                scope.owner(),
                                scope.repository(),
                                scope.branch(),
                                state.commitSha,
                                path,
                                sha,
                                size);
                sink.accept(source, bytes);
                state.objects.add(source);
                state.bytes += bytes.length;
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        } catch (GitHubSourceException e) {
            state.gaps.add(new Gap(path, map(e)));
        } catch (MalformedSourceException | IncompleteTreeException | IllegalArgumentException e) {
            state.gaps.add(new Gap(path, GapCode.MALFORMED_RESPONSE));
        }
        return state.result();
    }

    private String resolvePrefix(String base, String token, String rootSha, State state) {
        if (state.scope.pathPrefix().isEmpty()) return rootSha;
        String treeSha = rootSha;
        for (String segment :
                state.scope
                        .pathPrefix()
                        .substring(0, state.scope.pathPrefix().length() - 1)
                        .split("/")) {
            JsonNode entries = loadTree(base, token, treeSha, state);
            String childSha = null;
            for (JsonNode entry : entries) {
                if (segment.equals(entry.path("path").asText(""))
                        && "tree".equals(entry.path("type").asText(""))
                        && "040000".equals(entry.path("mode").asText(""))) {
                    childSha = checkedSha(entry.path("sha"));
                    break;
                }
            }
            if (childSha == null) return null;
            treeSha = childSha;
        }
        return treeSha;
    }

    private void collectTree(String base, String token, String prefixTreeSha, State state) {
        ArrayDeque<TreeAt> pending = new ArrayDeque<>();
        pending.add(new TreeAt(state.scope.pathPrefix(), prefixTreeSha, 0));
        while (!pending.isEmpty() && !state.stopped) {
            TreeAt current = pending.removeLast();
            JsonNode entries;
            try {
                entries = loadTree(base, token, current.sha(), state);
            } catch (GitHubSourceException e) {
                state.gaps.add(new Gap(current.path(), map(e)));
                if (e.code() == GitHubSourceException.Code.RATE_LIMITED) state.stopped = true;
                continue;
            } catch (IncompleteTreeException e) {
                state.gaps.add(new Gap(current.path(), e.code));
                continue;
            } catch (MalformedSourceException e) {
                state.gaps.add(new Gap(current.path(), GapCode.MALFORMED_RESPONSE));
                continue;
            }
            for (JsonNode entry : entries) {
                String name = entry.path("path").asText("");
                if (!validTreeName(name)) {
                    state.gaps.add(new Gap(current.path(), GapCode.MALFORMED_RESPONSE));
                    continue;
                }
                String path = current.path() + name;
                String type = entry.path("type").asText("");
                if ("tree".equals(type) && "040000".equals(entry.path("mode").asText(""))) {
                    if (current.depth() >= state.limits.maxDepth()) {
                        state.gaps.add(new Gap(path + "/", GapCode.DEPTH_LIMIT));
                    } else {
                        try {
                            pending.add(
                                    new TreeAt(
                                            path + "/",
                                            checkedSha(entry.path("sha")),
                                            current.depth() + 1));
                        } catch (MalformedSourceException e) {
                            state.gaps.add(new Gap(path + "/", GapCode.MALFORMED_RESPONSE));
                        }
                    }
                } else if ("blob".equals(type) && ("100644".equals(entry.path("mode").asText(""))
                        || "100755".equals(entry.path("mode").asText("")))) {
                    collectBlob(base, token, entry, path, state);
                } else {
                    state.gaps.add(new Gap(path, GapCode.UNSUPPORTED_OBJECT));
                }
                if (state.stopped) break;
            }
        }
    }

    private JsonNode loadTree(String base, String token, String sha, State state) {
        JsonNode tree;
        try {
            tree = api.get(base + "trees/" + sha, token, state.limits.maxJsonBytes());
        } catch (GitHubSourceException e) {
            if (e.code() == GitHubSourceException.Code.RESPONSE_TOO_LARGE) {
                throw new IncompleteTreeException(GapCode.TREE_LIMIT);
            }
            throw e;
        }
        if (!sha.equalsIgnoreCase(tree.path("sha").asText(""))) throw malformed();
        if (tree.path("truncated").asBoolean(false)) {
            throw new IncompleteTreeException(GapCode.TREE_TRUNCATED);
        }
        JsonNode entries = tree.path("tree");
        if (!entries.isArray()) throw malformed();
        state.treeEntries += entries.size();
        if (state.treeEntries > state.limits.maxTreeEntries()) {
            throw new IncompleteTreeException(GapCode.TREE_LIMIT);
        }
        return entries;
    }

    private void collectBlob(String base, String token, JsonNode entry, String path, State state) {
        long size = entry.path("size").asLong(-1);
        if (size < 0) {
            state.gaps.add(new Gap(path, GapCode.MALFORMED_RESPONSE));
            return;
        }
        if (state.objects.size() >= state.limits.maxFiles()) {
            state.gaps.add(new Gap(path, GapCode.FILE_LIMIT));
            state.stopped = true;
            return;
        }
        if (size > state.limits.maxFileBytes()) {
            state.gaps.add(new Gap(path, GapCode.FILE_TOO_LARGE));
            return;
        }
        if (size > state.limits.maxTotalBytes() - state.bytes) {
            state.gaps.add(new Gap(path, GapCode.TOTAL_BYTES_LIMIT));
            return;
        }
        try {
            String sha = checkedSha(entry.path("sha"));
            JsonNode blob = api.get(base + "blobs/" + sha, token, state.limits.maxJsonBytes());
            if (!sha.equalsIgnoreCase(blob.path("sha").asText(""))
                    || !"base64".equals(blob.path("encoding").asText(""))
                    || blob.path("size").asLong(-1) != size) throw malformed();
            String encoded = blob.path("content").asText("");
            byte[] bytes;
            try {
                bytes = Base64.getDecoder().decode(encoded.replaceAll("\\s", ""));
            } catch (IllegalArgumentException e) {
                throw malformed();
            }
            try {
                if (bytes.length != size) throw malformed();
                if (isBinary(bytes)) {
                    state.gaps.add(new Gap(path, GapCode.BINARY_FILE));
                    return;
                }
                if (new String(bytes, StandardCharsets.US_ASCII)
                        .startsWith("version https://git-lfs.github.com/spec/v1")) {
                    state.gaps.add(new Gap(path, GapCode.GIT_LFS_POINTER));
                    return;
                }
                Source source = new Source(state.scope.owner(), state.scope.repository(),
                        state.scope.branch(), state.commitSha, path, sha, size);
                try {
                    state.sink.accept(source, bytes);
                } catch (RuntimeException e) {
                    state.gaps.add(new Gap(path, GapCode.CONSUMER_FAILED));
                    state.stopped = true;
                    return;
                }
                state.objects.add(source);
                state.bytes += bytes.length;
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        } catch (GitHubSourceException e) {
            state.gaps.add(new Gap(path, e.code() == GitHubSourceException.Code.RESPONSE_TOO_LARGE
                    ? GapCode.FILE_TOO_LARGE : map(e)));
            if (e.code() == GitHubSourceException.Code.RATE_LIMITED) state.stopped = true;
        } catch (MalformedSourceException e) {
            state.gaps.add(new Gap(path, GapCode.MALFORMED_RESPONSE));
        }
    }

    private static boolean isBinary(byte[] bytes) {
        for (byte b : bytes) if (b == 0) return true;
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
            return false;
        } catch (CharacterCodingException e) {
            return true;
        }
    }

    private static boolean validTreeName(String name) {
        return !name.isBlank() && !name.equals(".") && !name.equals("..")
                && name.indexOf('/') < 0 && name.indexOf('\\') < 0
                && name.chars().noneMatch(c -> c < 32 || c == 127);
    }

    private static String checkedSha(JsonNode value) {
        String sha = value.asText("");
        if (!SHA.matcher(sha).matches()) throw malformed();
        return sha;
    }

    private static MalformedSourceException malformed() { return new MalformedSourceException(); }

    private static GapCode map(GitHubSourceException error) {
        return switch (error.code()) {
            case ACCESS_DENIED -> GapCode.ACCESS_DENIED;
            case RATE_LIMITED -> GapCode.RATE_LIMITED;
            case SOURCE_UNAVAILABLE -> GapCode.SOURCE_UNAVAILABLE;
            case API_ERROR -> GapCode.API_ERROR;
            case RESPONSE_TOO_LARGE -> GapCode.API_ERROR;
            case MALFORMED_RESPONSE -> GapCode.MALFORMED_RESPONSE;
        };
    }

    private record TreeAt(String path, String sha, int depth) { }
    private static final class MalformedSourceException extends RuntimeException { }
    private static final class IncompleteTreeException extends RuntimeException {
        private final GapCode code;
        IncompleteTreeException(GapCode code) { this.code = code; }
    }

    private static final class State {
        final GitHubApprovedScope scope;
        final GitHubCollectionLimits limits;
        final ContentSink sink;
        final List<Source> objects = new ArrayList<>();
        final List<Gap> gaps = new ArrayList<>();
        String commitSha;
        long bytes;
        int treeEntries;
        boolean stopped;

        State(GitHubApprovedScope scope, GitHubCollectionLimits limits, ContentSink sink) {
            this.scope = scope;
            this.limits = limits;
            this.sink = sink;
        }

        Result result() {
            Status status = gaps.isEmpty() ? Status.SUCCEEDED : objects.isEmpty() ? Status.FAILED : Status.PARTIAL;
            return new Result(status, commitSha, objects.size(), bytes, List.copyOf(objects), List.copyOf(gaps));
        }
    }
}
