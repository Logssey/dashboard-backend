package com.example.quotes;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Generic helper: calls readValue, but the target type is a parameter, so this method has no class literal. */
public final class JsonSupport {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonSupport() {
    }

    public static <T> T read(String json, Class<T> type) throws Exception {
        return MAPPER.readValue(json, type);
    }
}
