package com.logssey.help;

import java.util.List;
import java.util.Map;

/** Request and response shapes for /api/v1/help. */
final class HelpChatDtos {

    private HelpChatDtos() {
    }

    /** {@code mode} is "checklist" when the panel's checklist button was used; anything else means text. */
    record ChatRequest(String question, String page, List<HelpTurn> history, String mode, Map<String, Object> signals) {
        ChatRequest(String question, String page, List<HelpTurn> history, String mode) {
            this(question, page, history, mode, null);
        }

        ChatRequest(String question, String page, List<HelpTurn> history) {
            this(question, page, history, null, null);
        }
    }

    record SourceView(String doc, String title, String section) {
    }

    /** One checklist card. {@code screen} is a fixed key; the frontend maps it to a route. */
    record CardView(List<Integer> checks, List<String> titles, String screen, String focus) {
    }

    /** {@code cards} is null for text answers and for checklist fallbacks; {@code answer} is always set. */
    record ChatResponse(String answer, boolean grounded, List<SourceView> sources, int remainingToday,
                        boolean cached, List<CardView> cards) {
        ChatResponse(String answer, boolean grounded, List<SourceView> sources, int remainingToday, boolean cached) {
            this(answer, grounded, sources, remainingToday, cached, null);
        }
    }

    record StatusResponse(boolean ready, String reasonCode, int documentCount) {
    }

    /** Incident report draft (design doc 18.4). The notes are the user's own words; counts are added by the panel. */
    record ReportRequest(String memo) {
    }

    record ReportResponse(String summary, List<String> checked, List<String> actions, List<String> remaining,
                          int remainingToday) {
    }
}
