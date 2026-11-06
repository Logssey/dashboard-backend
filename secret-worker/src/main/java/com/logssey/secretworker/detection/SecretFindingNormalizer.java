package com.logssey.secretworker.detection;

import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.validation.AwsKeyMaterial;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Interprets detector positions against the in-memory source object. Neither raw
 * components nor the source text leave this class in its result or exception text.
 */
public final class SecretFindingNormalizer {
    private static final Pattern ASSIGNMENT =
            Pattern.compile(
                    "(?:^|[^A-Za-z0-9_])[\\\"']?(?<name>[A-Za-z][A-Za-z0-9_]*)[\\\"']?\\s*[:=]\\s*[\\\"']?(?<value>[A-Za-z0-9_+/=.\\-]+)");
    private static final Pattern AWS_ID = Pattern.compile("(?:AKIA|ASIA)[A-Z0-9]{16}");
    private static final Pattern AWS_SECRET = Pattern.compile("[A-Za-z0-9/+=]{40}");
    private static final Pattern GITHUB_CLASSIC = Pattern.compile("(?<![A-Za-z0-9_])ghp_[A-Za-z0-9_]{36}(?![A-Za-z0-9_])");
    private static final Pattern GITHUB_FINE = Pattern.compile("(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{70,}(?![A-Za-z0-9_])");
    private static final Pattern NOTION = Pattern.compile(
            "(?<![A-Za-z0-9_])(?:ntn_[A-Za-z0-9_]{46}|secret_[A-Za-z0-9]{43})(?![A-Za-z0-9_])");

    private final byte[] key;
    private final String keyVersion;

    public String keyVersion() {
        return keyVersion;
    }

    public SecretFindingNormalizer(byte[] fingerprintKey, String keyVersion) {
        if (fingerprintKey == null || fingerprintKey.length < 32 || keyVersion == null
                || !keyVersion.matches("[A-Za-z0-9_.-]{1,40}")) {
            throw new IllegalArgumentException("INVALID_FINGERPRINT_CONFIG");
        }
        this.key = fingerprintKey.clone();
        this.keyVersion = keyVersion;
    }

    public static SecretFindingNormalizer fromEnvironment() {
        return fromBase64(System.getenv("SECRET_FINGERPRINT_KEY_BASE64"),
                System.getenv("SECRET_FINGERPRINT_KEY_VERSION"));
    }

    /** Spring configuration may supply these values from a local .env properties file. */
    public static SecretFindingNormalizer fromBase64(String encoded, String version) {
        if (encoded == null || encoded.isBlank() || version == null || version.isBlank()) {
            throw new IllegalArgumentException("MISSING_FINGERPRINT_CONFIG");
        }
        byte[] decoded = null;
        try {
            decoded = java.util.Base64.getDecoder().decode(encoded);
            return new SecretFindingNormalizer(decoded, version);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("INVALID_FINGERPRINT_CONFIG");
        } finally {
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
        }
    }

    public List<Credential> normalize(long connectionId, String sourceObjectRef, byte[] utf8Content,
                                      List<GitleaksFinding> findings) {
        return inspect(connectionId, sourceObjectRef, utf8Content, findings).credentials();
    }

    /** One parse gives persistence metadata and temporary AWS material for the validator. */
    public Inspection inspect(long connectionId, String sourceObjectRef, byte[] utf8Content,
                              List<GitleaksFinding> findings) {
        if (connectionId <= 0 || sourceObjectRef == null || sourceObjectRef.isBlank()
                || sourceObjectRef.length() > 500 || utf8Content == null || findings == null) {
            throw new IllegalArgumentException("INVALID_NORMALIZATION_INPUT");
        }
        String content;
        try {
            content = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(utf8Content)).toString();
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("INVALID_UTF8_CONTENT");
        }
        String[] lines = content.split("\\R", -1);
        List<Component> ids = new ArrayList<>();
        List<Component> secrets = new ArrayList<>();
        List<Component> tokens = new ArrayList<>();
        Set<GitleaksFinding> seen = new HashSet<>();
        for (GitleaksFinding finding : findings) {
            if (finding == null || !seen.add(finding) || finding.startLine() != finding.endLine()
                    || finding.startLine() < 1 || finding.startLine() > lines.length) continue;
            String line = lines[finding.startLine() - 1];
            Pattern tokenPattern = switch (finding.ruleId()) {
                case "notion-api-token" -> NOTION;
                case "github-pat" -> GITHUB_CLASSIC;
                case "github-fine-grained-pat" -> GITHUB_FINE;
                default -> null;
            };
            List<Assignment> assignments = tokenPattern == null
                    ? assignments(line) : tokenValues(line, tokenPattern);
            List<Assignment> matches = assignments.stream()
                    .filter(item -> overlaps(finding, line, item)
                            && matches(finding.ruleId(), item)).toList();
            // Two possible values on one line cannot be attributed to one detector position safely.
            if (matches.size() != 1) continue;
            Assignment assignment = matches.getFirst();
            String role = role(finding.ruleId(), assignment);
            Component component = new Component(role, assignment.value(), qualifier(assignment.name(), role),
                    finding.startLine(), finding);
            if (role.equals("ACCESS_KEY_ID")) ids.add(component);
            else if (role.equals("SECRET_ACCESS_KEY")) secrets.add(component);
            else tokens.add(component);
        }

        List<Credential> result = new ArrayList<>();
        List<AwsCandidate> awsCandidates = new ArrayList<>();
        List<GitHubCandidate> githubCandidates = new ArrayList<>();
        List<NotionCandidate> notionCandidates = new ArrayList<>();
        Set<Component> pairedSecrets = new HashSet<>();
        for (Component id : ids) {
            List<Component> eligibleSecrets = secrets.stream()
                    .filter(secret -> secret.qualifier().equals(id.qualifier())
                            && Math.abs(secret.line() - id.line()) <= 3).toList();
            long eligibleIds = ids.stream().filter(other -> other.qualifier().equals(id.qualifier())
                    && Math.abs(other.line() - eligibleSecrets.stream()
                            .mapToInt(Component::line).findFirst().orElse(id.line())) <= 3).count();
            Component secret = eligibleSecrets.size() == 1 && eligibleIds == 1
                    ? eligibleSecrets.getFirst() : null;
            if (secret != null) pairedSecrets.add(secret);
            boolean temporary = id.value().startsWith("ASIA");
            String type = temporary ? "AWS_TEMPORARY_CREDENTIALS" : "AWS_ACCESS_KEY_PAIR";
            Component session = temporary && secret != null
                    ? findSession(lines, id.qualifier(), id.line(), secret.line()) : null;
            boolean complete = secret != null && (!temporary || session != null);
            int first = secret == null ? id.line() : Math.min(id.line(), secret.line());
            int last = secret == null ? id.line() : Math.max(id.line(), secret.line());
            if (session != null) {
                first = Math.min(first, session.line());
                last = Math.max(last, session.line());
            }
            String location = location(first, last);
            List<Component> components = new ArrayList<>(List.of(id));
            if (secret != null) components.add(secret);
            if (session != null) components.add(session);
            Credential normalized =
                    credential(
                            connectionId,
                            sourceObjectRef,
                            "AWS",
                            type,
                            complete,
                            location,
                            mask("AWS", id.value(), 4),
                            components);
            result.add(normalized);
            awsCandidates.add(new AwsCandidate(normalized, new AwsKeyMaterial(id.value(),
                    secret == null ? null : secret.value(), session == null ? null : session.value())));
        }
        for (Component secret : secrets) {
            if (!pairedSecrets.contains(secret)) {
                Credential normalized =
                        credential(
                                connectionId,
                                sourceObjectRef,
                                "AWS",
                                "AWS_ACCESS_KEY_PAIR",
                                false,
                                location(secret.line(), secret.line()),
                                "AWS secret ••••",
                                List.of(secret));
                result.add(normalized);
                awsCandidates.add(new AwsCandidate(normalized, new AwsKeyMaterial(null, secret.value(), null)));
            }
        }
        for (Component token : tokens) {
            String issuer = token.role().equals("NOTION_TOKEN") ? "NOTION" : "GITHUB";
            String type = switch (token.role()) {
                case "GITHUB_CLASSIC" -> "GITHUB_CLASSIC_PAT";
                case "GITHUB_FINE" -> "GITHUB_FINE_GRAINED_PAT";
                case "NOTION_TOKEN" -> "NOTION_CONNECTION_TOKEN";
                default -> throw new IllegalStateException("UNKNOWN_TOKEN_ROLE");
            };
            Credential normalized =
                    credential(
                            connectionId,
                            sourceObjectRef,
                            issuer,
                            type,
                            true,
                            location(token.line(), token.line()),
                            mask(issuer, token.value(), 4),
                            List.of(token));
            result.add(normalized);
            if ("GITHUB".equals(issuer))
                githubCandidates.add(new GitHubCandidate(normalized, token.value()));
            else if ("NOTION".equals(issuer))
                notionCandidates.add(new NotionCandidate(normalized, token.value()));
        }
        return new Inspection(
                connectionId,
                sourceObjectRef,
                List.copyOf(findings),
                List.copyOf(result),
                List.copyOf(awsCandidates),
                List.copyOf(githubCandidates),
                List.copyOf(notionCandidates));
    }

    private static List<Assignment> tokenValues(String line, Pattern pattern) {
        var tokens = new ArrayList<Assignment>();
        var matcher = pattern.matcher(line);
        while (matcher.find()) {
            tokens.add(new Assignment("CONTENT_TOKEN", matcher.group(), matcher.start(), matcher.end()));
        }
        return tokens;
    }

    private static boolean overlaps(GitleaksFinding finding, String line, Assignment value) {
        // Gitleaks columns are UTF-8 byte offsets, while regex offsets are Java character offsets.
        int byteStart = line.substring(0, value.start()).getBytes(StandardCharsets.UTF_8).length;
        int byteEnd = byteStart + value.end() - value.start(); // Supported values are ASCII.
        return finding.startColumn() - 1 < byteEnd && finding.endColumn() > byteStart;
    }

    private Credential credential(long connectionId, String source, String issuer, String type,
                                  boolean complete, String location, String label, List<Component> components) {
        Map<String, String> values = new HashMap<>();
        for (Component component : components) values.put(component.role(), component.value());
        List<String> names = values.keySet().stream().sorted().toList();
        List<String> identity = new ArrayList<>(List.of(issuer, type));
        if (!complete) identity.addAll(List.of(Long.toString(connectionId), source, location));
        for (String name : names) identity.addAll(List.of(name, values.get(name)));
        byte[] digest = hmac(identity);
        List<GitleaksFinding> evidence = components.stream().map(Component::finding)
                .filter(Objects::nonNull).distinct().toList();
        List<byte[]> promotionLocators=new ArrayList<>();
        // Recompute the exact protected identity of prior partial components in this same object.
        // Neither a common masked suffix nor a nearby line establishes candidate identity.
        if(complete&&"AWS".equals(issuer)&&components.size()<=3) {
            for(int subset=1;subset<(1<<components.size())-1;subset++) {
                List<Component> partial=new ArrayList<>();for(int i=0;i<components.size();i++)if((subset&(1<<i))!=0)partial.add(components.get(i));
                String partialLocation=location(partial.stream().mapToInt(Component::line).min().orElseThrow(),partial.stream().mapToInt(Component::line).max().orElseThrow());
                List<String> fields=new ArrayList<>(List.of(issuer,type,Long.toString(connectionId),source,partialLocation));
                partial.stream().sorted(java.util.Comparator.comparing(Component::role)).forEach(c->{fields.add(c.role());fields.add(c.value());});
                promotionLocators.add(hmac(fields));
            }
        }
        return new Credential(issuer, type, complete ? "CONFIRMED" : "CANDIDATE",
                complete ? digest : null, complete ? null : digest, keyVersion, label, location, evidence,promotionLocators);
    }

    private byte[] hmac(List<String> fields) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String field : fields) {
                byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
                mac.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
                mac.update(bytes);
                Arrays.fill(bytes, (byte) 0);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("FINGERPRINT_UNAVAILABLE");
        }
    }

    private static Component findSession(String[] lines, String qualifier, int idLine, int secretLine) {
        int first = Math.max(1, Math.min(idLine, secretLine) - 3);
        int last = Math.min(lines.length, Math.max(idLine, secretLine) + 3);
        List<Component> matches = new ArrayList<>();
        for (int line = first; line <= last; line++) {
            for (Assignment assignment : assignments(lines[line - 1])) {
                if (roleForName(assignment.name()).equals("SESSION_TOKEN")
                        && qualifier(assignment.name(), "SESSION_TOKEN").equals(qualifier)
                        && assignment.value().length() >= 20) {
                    matches.add(
                            new Component(
                                    "SESSION_TOKEN", assignment.value(), qualifier, line, null));
                }
            }
        }
        return matches.size() == 1 ? matches.getFirst() : null;
    }

    private static List<Assignment> assignments(String line) {
        List<Assignment> result = new ArrayList<>();
        Matcher matcher = ASSIGNMENT.matcher(line);
        while (matcher.find())
            result.add(
                    new Assignment(
                            matcher.group("name"),
                            matcher.group("value"),
                            matcher.start("name"),
                            matcher.end("value")));
        return result;
    }

    private static boolean matches(String ruleId, Assignment assignment) {
        String nameRole = roleForName(assignment.name());
        return switch (ruleId) {
            case "aws-access-token" -> nameRole.equals("ACCESS_KEY_ID")
                    && AWS_ID.matcher(assignment.value()).matches();
            case "generic-api-key" -> nameRole.equals("SECRET_ACCESS_KEY")
                    && AWS_SECRET.matcher(assignment.value()).matches();
            case "github-pat" -> GITHUB_CLASSIC.matcher(assignment.value()).matches();
            case "github-fine-grained-pat" -> GITHUB_FINE.matcher(assignment.value()).matches();
            case "notion-api-token" -> NOTION.matcher(assignment.value()).matches();
            default -> false;
        };
    }

    private static String role(String ruleId, Assignment assignment) {
        return switch (ruleId) {
            case "aws-access-token" -> "ACCESS_KEY_ID";
            case "generic-api-key" -> "SECRET_ACCESS_KEY";
            case "github-pat" -> "GITHUB_CLASSIC";
            case "github-fine-grained-pat" -> "GITHUB_FINE";
            case "notion-api-token" -> "NOTION_TOKEN";
            default -> throw new IllegalStateException("UNKNOWN_RULE");
        };
    }

    private static String roleForName(String name) {
        String compact = name.toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]", "");
        if (compact.contains("AWS") && compact.endsWith("ACCESSKEYID")) return "ACCESS_KEY_ID";
        if (compact.contains("AWS") && compact.endsWith("SECRETACCESSKEY"))
            return "SECRET_ACCESS_KEY";
        if (compact.contains("AWS") && compact.endsWith("SESSIONTOKEN")) return "SESSION_TOKEN";
        return "OTHER";
    }

    private static String qualifier(String name, String role) {
        if (!(role.equals("ACCESS_KEY_ID")
                || role.equals("SECRET_ACCESS_KEY")
                || role.equals("SESSION_TOKEN"))) return "";
        String compact = name.toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]", "");
        String suffix = switch (role) {
            case "ACCESS_KEY_ID" -> "ACCESSKEYID";
            case "SECRET_ACCESS_KEY" -> "SECRETACCESSKEY";
            default -> "SESSIONTOKEN";
        };
        return compact.substring(0, compact.length() - suffix.length()).replace("AWS", "");
    }

    private static String location(int first, int last) {
        return first == last ? "L" + first : "L" + first + "-" + last;
    }

    private static String mask(String issuer, String value, int prefixLength) {
        return issuer
                + " "
                + value.substring(0, prefixLength)
                + "••••"
                + value.substring(value.length() - 4);
    }

    private record Assignment(String name, String value, int start, int end) { }
    private record Component(String role, String value, String qualifier, int line, GitleaksFinding finding) { }

    public record Credential(String issuer, String credentialType, String componentState,
                             byte[] fingerprint, byte[] candidateLocator, String fingerprintKeyVersion,
                             String maskedLabel, String locationKey, List<GitleaksFinding> findings,List<byte[]> promotionLocators) {
        public Credential {
            fingerprint = fingerprint == null ? null : fingerprint.clone();
            candidateLocator = candidateLocator == null ? null : candidateLocator.clone();
            findings = List.copyOf(findings);
            promotionLocators=promotionLocators.stream().map(byte[]::clone).toList();
        }
        @Override public byte[] fingerprint() { return fingerprint == null ? null : fingerprint.clone(); }
        @Override public byte[] candidateLocator() { return candidateLocator == null ? null : candidateLocator.clone(); }
        @Override public List<byte[]> promotionLocators(){return promotionLocators.stream().map(byte[]::clone).toList();}
        @Override public String toString() {
            return "Credential[issuer=" + issuer + ", credentialType=" + credentialType
                    + ", componentState=" + componentState + ", locationKey=" + locationKey + "]";
        }
    }

    public record Inspection(
            long connectionId,
            String sourceObjectRef,
            List<GitleaksFinding> detectorFindings,
            List<Credential> credentials,
            List<AwsCandidate> awsCandidates,
            List<GitHubCandidate> githubCandidates,
            List<NotionCandidate> notionCandidates) {
        public Inspection(
                long connectionId,
                String sourceObjectRef,
                List<GitleaksFinding> detectorFindings,
                List<Credential> credentials,
                List<AwsCandidate> awsCandidates,
                List<GitHubCandidate> githubCandidates) {
            this(connectionId, sourceObjectRef, detectorFindings, credentials,
                    awsCandidates, githubCandidates, List.of());
        }

        public Inspection(
                long connectionId,
                String sourceObjectRef,
                List<GitleaksFinding> detectorFindings,
                List<Credential> credentials,
                List<AwsCandidate> awsCandidates) {
            this(
                    connectionId,
                    sourceObjectRef,
                    detectorFindings,
                    credentials,
                    awsCandidates,
                    List.of());
        }

        public Inspection {
            detectorFindings = List.copyOf(detectorFindings);
            credentials = List.copyOf(credentials);
            awsCandidates = List.copyOf(awsCandidates);
            githubCandidates = List.copyOf(githubCandidates);
            notionCandidates = List.copyOf(notionCandidates);
        }
        @Override public String toString() {
            return "Inspection[credentialCount=" + credentials.size()
                    + ", awsCandidateCount=" + awsCandidates.size() + "]";
        }
    }

    /** In-memory only; never serialize, persist or log the token. */
    public static final class NotionCandidate {
        private final Credential credential;
        private final String token;

        private NotionCandidate(Credential credential, String token) {
            this.credential = credential;
            this.token = token;
        }

        public Credential credential() {
            return credential;
        }

        public String token() {
            return token;
        }

        @Override
        public String toString() {
            return "NotionCandidate[credentialType=" + credential.credentialType() + "]";
        }
    }

    /** In-memory only; safe summary is the sole permitted string representation. */
    public static final class GitHubCandidate {
        private final Credential credential;
        private final String token;

        private GitHubCandidate(Credential credential, String token) {
            this.credential = credential;
            this.token = token;
        }

        public Credential credential() {
            return credential;
        }

        public String token() {
            return token;
        }

        @Override
        public String toString() {
            return "GitHubCandidate[credentialType=" + credential.credentialType() + "]";
        }
    }

    /** Keep only within the collector callback; never serialize, persist, or log this object. */
    public static final class AwsCandidate {
        private final Credential credential;
        private final AwsKeyMaterial material;

        private AwsCandidate(Credential credential, AwsKeyMaterial material) {
            this.credential = credential;
            this.material = material;
        }

        public Credential credential() { return credential; }
        public AwsKeyMaterial material() { return material; }
        @Override public String toString() { return "AwsCandidate[REDACTED]"; }
    }
}
