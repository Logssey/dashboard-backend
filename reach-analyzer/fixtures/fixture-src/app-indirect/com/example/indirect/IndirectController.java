package com.example.indirect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Same CVE conditions as app-positive, one step removed: nesting, generics, field annotations, ObjectReader. */
@RestController
public class IndirectController {
    private static final ObjectReader MAP_READER = new ObjectMapper().readerFor(Map.class);

    @PostMapping("/order")
    public int order(@RequestBody OrderRequest request) {
        return request.lines().size();
    }

    @PostMapping("/schedule")
    public String schedule(@RequestBody ScheduleRequest request) {
        return String.valueOf(request.window());
    }

    @PostMapping("/pet")
    public String pet(@RequestBody PetRequest request) {
        return String.valueOf(request.pet());
    }

    /** The root itself is the container (no wrapper DTO). */
    @PostMapping("/ledger")
    public int ledger(@RequestBody Map<String, Account> accounts) {
        return accounts.size();
    }

    @PostMapping("/datainput")
    public int dataInput(@RequestBody byte[] body) throws Exception {
        Map<?, ?> m = MAP_READER.readValue((DataInput) new DataInputStream(new ByteArrayInputStream(body)));
        return m.size();
    }
}
