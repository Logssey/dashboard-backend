package com.reused.chat;

import java.time.Instant;

public record ChatMessage(String roomId, String sender, String content, Instant sentAt) {
}
