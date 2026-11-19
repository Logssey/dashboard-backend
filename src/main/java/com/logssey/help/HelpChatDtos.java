package com.logssey.help;

import java.util.List;

/** Request and response shapes for /api/v1/help. */
final class HelpChatDtos {

    private HelpChatDtos() {
    }

    record ChatRequest(String question, String page, List<HelpTurn> history) {
    }

    record SourceView(String doc, String title, String section) {
    }

    record ChatResponse(String answer, boolean grounded, List<SourceView> sources, int remainingToday,
                        boolean cached) {
    }

    record StatusResponse(boolean ready, String reasonCode, int documentCount) {
    }
}
