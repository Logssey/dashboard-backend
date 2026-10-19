package com.logssey.iacworker.graph;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/** 로컬 개발용: {"노드 이름":"InternalIP"} JSON 파일. 경로가 비어 있으면 연결하지 않는다. */
public class FileNodeAddresses implements NodeAddresses {

    private final String path;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public FileNodeAddresses(String path) {
        this.path = path;
    }

    @Override
    public Map<String, String> byNodeName() {
        if (path == null || path.isBlank()) {
            return Map.of();
        }
        try {
            return mapper.readValue(Files.readString(Path.of(path)), new TypeReference<Map<String, String>>() { });
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Node address file is unreadable", e);
        }
    }
}
