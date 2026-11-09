package com.example.risky;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.DataInput;
import java.io.IOException;
import org.springframework.stereotype.Service;

/** Parses JSON from a DataInput (CVE-2026-89425). */
@Service
public class DataInputReader {
    private final ObjectMapper mapper = new ObjectMapper();

    public Object read(DataInput in) throws IOException {
        return mapper.readValue(in, Object.class);
    }
}
