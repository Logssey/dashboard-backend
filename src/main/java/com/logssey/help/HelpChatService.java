package com.logssey.help;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.logssey.help.HelpChatDtos.CardView;
import com.logssey.help.HelpChatDtos.ChatRequest;
import com.logssey.help.HelpChatDtos.ChatResponse;
import com.logssey.help.HelpChatDtos.ReportRequest;
import com.logssey.help.HelpChatDtos.ReportResponse;
import com.logssey.help.HelpChatDtos.SourceView;
import com.logssey.help.HelpChatDtos.StatusResponse;

/**
 * Usage-help chat. Reads nothing but the approved guides and uses no database.
 * Question and answer text are never logged or stored.
 */
@Service
class HelpChatService {

    static final int MAX_QUESTION_CHARS = 1_000;
    static final int MAX_TURN_CHARS = 1_000;
    static final int MAX_HISTORY_MESSAGES = 6;
    static final int MAX_PAGE_CHARS = 40;
    static final String NOT_FOUND_ANSWER =
            "가이드 문서에서 찾지 못했어요. 메뉴 이름이나 하려는 작업을 넣어 다시 물어봐 주세요. "
                    + "예: \"대응 건은 어떻게 만들어요?\"";
    private static final Pattern PAGE_TEXT = Pattern.compile("[\\p{IsHangul}A-Za-z0-9 ·:/()-]{1,40}");
    private static final Duration CACHE_TTL = Duration.ofMinutes(10);
    private static final int MAX_CACHE_ENTRIES = 200;
    private static final Logger log = LoggerFactory.getLogger(HelpChatService.class);

    private final HelpDocumentLibrary library;
    private final ClaudeHelpProvider provider;
    private final HelpCallBudget budget;
    private final Map<String, CachedAnswer> cache = new LinkedHashMap<>();

    HelpChatService(HelpDocumentLibrary library, ClaudeHelpProvider provider, HelpCallBudget budget) {
        this.library = library;
        this.provider = provider;
        this.budget = budget;
    }

    StatusResponse status() {
        String reason = readiness();
        return new StatusResponse("READY".equals(reason), reason, library.documents().size());
    }

    ChatResponse chat(String principal, ChatRequest request) {
        Prepared prepared = prepare(request);
        String question = prepared.question();
        String page = prepared.page();
        List<HelpTurn> history = prepared.history();
        Map<String, Boolean> signals = prepared.signals();

        String reason = readiness();
        if (!"READY".equals(reason)) throw new HelpChatException("NOT_CONFIGURED");

        HelpDocument playbook = prepared.checklist() ? playbook() : null;
        String normalized = question.replaceAll("\\s+", " ") + "\n" + signals;
        // Checklist answers ignore history, so they can always be cached.
        String cacheKey = playbook != null ? "checklist\n" + page + "\n" + normalized
                : history.isEmpty() ? page + "\n" + normalized : null;
        if (cacheKey != null) {
            var hit = cachedAnswer(cacheKey, budget.remainingToday(principal));
            if (hit != null) return hit;
        }

        var permit = budget.acquire(principal);
        if (!permit.allowed()) {
            throw new HelpChatException(permit.reasonCode(), permit.retryAfterSeconds());
        }

        if (playbook != null) {
            ChatResponse response = checklist(playbook, page, question, signals, permit);
            // A playbook-only answer after a provider failure is not cached, so the next ask tries the model again.
            if (!response.withoutAi()) remember(cacheKey, response);
            return response;
        }

        HelpAnswerFilter.Result result;
        try {
            var documents = library.documents();
            var reply = provider.send(provider.requestBody(documents, page, history, question, signals));
            result = reply.reasonCode() != null
                    ? HelpAnswerFilter.Result.failed(reply.reasonCode(), HelpAnswerFilter.Usage.EMPTY)
                    : HelpAnswerFilter.parse(reply.body(), documents);
        } catch (RuntimeException unexpected) {
            result = HelpAnswerFilter.Result.failed("PROVIDER_UNAVAILABLE", HelpAnswerFilter.Usage.EMPTY);
        } finally {
            permit.complete();
        }
        String code = result.ok() ? "ANSWERED" : result.reasonCode();
        log.info("Help chat result={} input={} cacheRead={} cacheWrite={} output={}", code,
                result.usage().input(), result.usage().cacheRead(), result.usage().cacheWrite(), result.usage().output());

        ChatResponse response;
        if (result.ok()) {
            response = new ChatResponse(result.answer(), true, result.sources().stream()
                    .map(s -> new SourceView(s.doc(), s.title(), s.section())).toList(), permit.remainingToday(), false);
        } else if ("NO_GROUNDED_ANSWER".equals(result.reasonCode())) {
            response = new ChatResponse(NOT_FOUND_ANSWER, false, List.of(), permit.remainingToday(), false);
        } else {
            throw new HelpChatException(result.reasonCode().startsWith("PROVIDER_") || "ANSWER_BLOCKED".equals(result.reasonCode())
                    ? "PROVIDER_UNAVAILABLE" : result.reasonCode());
        }
        if (cacheKey != null) remember(cacheKey, response);
        return response;
    }

    /** What is sent to the model after every input check (design doc 18.1, 18.3, 18.7). */
    record Prepared(String question, String page, List<HelpTurn> history, Map<String, Boolean> signals, boolean checklist) {
    }

    /**
     * The input path shared by {@link #chat} and the live model evaluation (design doc 18.8): length check, key check on
     * the original text, customer-data masking of the question and every earlier turn, key check again, page and
     * history cleaning, yes/no signals, and the card-mode decision. Throws INVALID_INPUT or QUESTION_REJECTED.
     */
    static Prepared prepare(ChatRequest request) {
        if (request == null || request.question() == null) throw new HelpChatException("INVALID_INPUT");
        String question = request.question().strip();
        if (question.isEmpty() || question.length() > MAX_QUESTION_CHARS) throw new HelpChatException("INVALID_INPUT");
        String page = cleanPage(request.page());
        List<HelpTurn> rawHistory = cleanHistory(request.history());
        // Check the original text too: masking a digit run inside a key could shorten what is left below the
        // long-token threshold (design doc 18.7).
        if (HelpQuestionGuard.containsSecretLikeValue(question)
                || rawHistory.stream().anyMatch(turn -> HelpQuestionGuard.containsSecretLikeValue(turn.text()))) {
            log.info("Help chat rejected a secret-like question before dispatch");
            throw new HelpChatException("QUESTION_REJECTED");
        }
        // Customer data (e-mail, IP, phone, ...) is masked in the question and in every earlier turn (design doc 18.1).
        question = HelpPrivacyMask.mask(question);
        List<HelpTurn> history = rawHistory.stream()
                .map(turn -> new HelpTurn(turn.role(), HelpPrivacyMask.mask(turn.text()))).toList();
        // Never send credential-looking text to the provider, even from earlier turns.
        if (HelpQuestionGuard.containsSecretLikeValue(question)
                || history.stream().anyMatch(turn -> HelpQuestionGuard.containsSecretLikeValue(turn.text()))) {
            log.info("Help chat rejected a secret-like question before dispatch");
            throw new HelpChatException("QUESTION_REJECTED");
        }
        // Yes/no environment signals only (design doc 18.3); unknown keys and non-booleans are dropped.
        Map<String, Boolean> signals = HelpSignals.clean(request.signals());
        return new Prepared(question, page, history, signals, HelpChecklist.wanted(request.mode(), question));
    }

    /** Cards when the model JSON passes every check; otherwise the playbook text, without a second call. */
    private ChatResponse checklist(HelpDocument playbook, String page, String question, Map<String, Boolean> signals,
                                   HelpCallBudget.Permit permit) {
        HelpChecklist.Result result;
        try {
            var reply = provider.send(provider.checklistRequestBody(playbook, page, question, signals));
            // A provider failure (timeout, 429, 5xx) still answers with the playbook's fixed ten checks (design doc 18.7).
            result = reply.reasonCode() != null
                    ? HelpChecklist.fallback(playbook, reply.reasonCode(), HelpAnswerFilter.Usage.EMPTY)
                    : HelpChecklist.parse(reply.body(), playbook);
        } catch (RuntimeException unexpected) {
            result = HelpChecklist.fallback(playbook, "PROVIDER_UNAVAILABLE", HelpAnswerFilter.Usage.EMPTY);
        } finally {
            permit.complete();
        }
        log.info("Help chat result={} mode=checklist input={} cacheRead={} cacheWrite={} output={}",
                result.fallback() ? "CHECKLIST_FALLBACK:" + result.reasonCode() : "CHECKLIST",
                result.usage().input(), result.usage().cacheRead(), result.usage().cacheWrite(), result.usage().output());
        var sources = result.sources().stream().map(s -> new SourceView(s.doc(), s.title(), s.section())).toList();
        var cards = result.fallback() ? null : result.cards().stream()
                .map(c -> new CardView(c.checks(), c.titles(), c.screen(), c.focus())).toList();
        // withoutAi: the text is the playbook itself, not the model's wording.
        return new ChatResponse(result.text(), true, sources, permit.remainingToday(), false, cards, result.fallback());
    }

    private HelpDocument playbook() {
        return library.documents().stream()
                .filter(doc -> HelpChecklist.PLAYBOOK_FILE.equals(doc.file())).findFirst().orElse(null);
    }

    /**
     * Incident report draft (design doc 18.4): the user's notes, masked like questions, become report sentences.
     * Counts and times are added by the panel from Logssey data. Shares the same call budget as questions.
     */
    ReportResponse report(String principal, ReportRequest request) {
        if (request == null || request.memo() == null) throw new HelpChatException("MEMO_INVALID");
        String memo = request.memo().strip();
        if (memo.isEmpty() || memo.length() > HelpReport.MAX_MEMO_CHARS) throw new HelpChatException("MEMO_INVALID");
        boolean rawSecret = HelpQuestionGuard.containsSecretLikeValue(memo);
        memo = HelpPrivacyMask.mask(memo);
        if (rawSecret || HelpQuestionGuard.containsSecretLikeValue(memo)) {
            log.info("Help report rejected secret-like notes before dispatch");
            throw new HelpChatException("QUESTION_REJECTED");
        }
        if (!"READY".equals(readiness())) throw new HelpChatException("NOT_CONFIGURED");

        var permit = budget.acquire(principal);
        if (!permit.allowed()) throw new HelpChatException(permit.reasonCode(), permit.retryAfterSeconds());
        HelpReport.Result result;
        try {
            var reply = provider.send(provider.reportRequestBody(memo));
            result = reply.reasonCode() != null
                    ? new HelpReport.Result(null, reply.reasonCode(), HelpAnswerFilter.Usage.EMPTY)
                    : HelpReport.parse(reply.body(), memo);
        } catch (RuntimeException unexpected) {
            result = new HelpReport.Result(null, "PROVIDER_UNAVAILABLE", HelpAnswerFilter.Usage.EMPTY);
        } finally {
            permit.complete();
        }
        log.info("Help report result={} input={} output={}", result.ok() ? "DRAFTED" : result.reasonCode(),
                result.usage().input(), result.usage().output());
        if (!result.ok()) {
            throw new HelpChatException("REPORT_BLOCKED".equals(result.reasonCode()) ? "REPORT_BLOCKED" : "PROVIDER_UNAVAILABLE");
        }
        var draft = result.draft();
        return new ReportResponse(draft.summary(), draft.checked(), draft.actions(), draft.remaining(), permit.remainingToday());
    }

    private String readiness() {
        if (library.documents().isEmpty()) return "NO_DOCUMENTS";
        return provider.configurationReason();
    }

    static String cleanPage(String page) {
        if (page == null) return "";
        String value = page.strip();
        return PAGE_TEXT.matcher(value).matches() && value.length() <= MAX_PAGE_CHARS ? value : "";
    }

    /** Keeps the newest messages, starting with a user turn and alternating; anything malformed drops history. */
    static List<HelpTurn> cleanHistory(List<HelpTurn> history) {
        if (history == null || history.isEmpty()) return List.of();
        var turns = new ArrayList<HelpTurn>();
        for (var turn : history) {
            if (turn == null || turn.text() == null || turn.text().isBlank()) return List.of();
            if (!"user".equals(turn.role()) && !"assistant".equals(turn.role())) return List.of();
            String text = turn.text().strip();
            if (text.length() > MAX_TURN_CHARS) text = text.substring(0, MAX_TURN_CHARS);
            turns.add(new HelpTurn(turn.role(), text));
        }
        int from = Math.max(0, turns.size() - MAX_HISTORY_MESSAGES);
        var recent = new ArrayList<>(turns.subList(from, turns.size()));
        if (!recent.isEmpty() && "assistant".equals(recent.get(0).role())) recent.remove(0);
        for (int i = 0; i < recent.size(); i++) {
            String expected = i % 2 == 0 ? "user" : "assistant";
            if (!expected.equals(recent.get(i).role())) return List.of();
        }
        if (!recent.isEmpty() && !"assistant".equals(recent.get(recent.size() - 1).role())) return List.of();
        return List.copyOf(recent);
    }

    /** A cached answer, with the asking user's own remaining count rather than the first asker's. */
    private synchronized ChatResponse cachedAnswer(String key, int remainingToday) {
        long now = System.nanoTime();
        cache.values().removeIf(entry -> now - entry.expiresAt() >= 0);
        var entry = cache.get(key);
        if (entry == null) return null;
        var value = entry.response();
        return new ChatResponse(value.answer(), value.grounded(), value.sources(), remainingToday, true,
                value.cards(), value.withoutAi());
    }

    private synchronized void remember(String key, ChatResponse response) {
        if (cache.size() >= MAX_CACHE_ENTRIES) cache.remove(cache.keySet().iterator().next());
        cache.put(key, new CachedAnswer(response, System.nanoTime() + CACHE_TTL.toNanos()));
    }

    private record CachedAnswer(ChatResponse response, long expiresAt) {
    }

    static final class HelpChatException extends RuntimeException {
        private final String code;
        private final int retryAfterSeconds;

        HelpChatException(String code) {
            this(code, 0);
        }

        HelpChatException(String code, int retryAfterSeconds) {
            super(code, null, false, false);
            this.code = code;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        String code() { return code; }
        int retryAfterSeconds() { return retryAfterSeconds; }
    }
}
