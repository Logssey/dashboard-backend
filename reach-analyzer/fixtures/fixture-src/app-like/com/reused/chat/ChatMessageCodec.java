package com.reused.chat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

/** Reads chat messages from a broker with Jackson (an app-side deserialisation root). */
@Service
public class ChatMessageCodec {
    private final ObjectMapper mapper = new ObjectMapper();

    public ChatMessage decode(String json) throws Exception {
        return mapper.readValue(json, ChatMessage.class);
    }

    public String encode(ChatMessage message) throws Exception {
        return mapper.writeValueAsString(message);
    }
}
