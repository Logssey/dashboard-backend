package com.logssey.help;

import java.util.List;

/** Request and response shapes for /api/v1/help. */
final class HelpChatDtos {

    private HelpChatDtos() {
    }

    /** {@code mode} is "checklist" when the panel's checklist button was used; anything else means text. */
    record ChatRequest(String question, String page, List<HelpTurn> history, String mode) {
        ChatRequest(String question, String page, List<HelpTurn> history) {
            this(question, page, history, null);
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
}
