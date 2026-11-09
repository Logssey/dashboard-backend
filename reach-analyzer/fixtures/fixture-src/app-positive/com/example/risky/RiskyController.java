package com.example.risky;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RiskyController {
    private final LegacyCrypto crypto;
    private final CertReview certs;

    public RiskyController(LegacyCrypto crypto, CertReview certs) {
        this.crypto = crypto;
        this.certs = certs;
    }

    @PostMapping("/measure")
    public String measure(@RequestBody MeasurementRequest request) {
        return String.valueOf(request.value());
    }

    @PostMapping("/graph")
    public int graph(@RequestBody GraphRequest request) {
        return request.nodes == null ? 0 : request.nodes.size();
    }

    @PostMapping("/encrypt")
    public byte[] encrypt(@RequestBody byte[] data) {
        return crypto.gostEncrypt(new byte[32], new byte[8], data);
    }
}
