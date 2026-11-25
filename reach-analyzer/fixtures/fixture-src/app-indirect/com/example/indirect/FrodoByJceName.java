package com.example.indirect;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.springframework.stereotype.Service;

/** FrodoKEM selected by its JCE name (CVE-2026-5598): no BC class is named, so the call graph cannot confirm it. */
@Service
public class FrodoByJceName {
    public KeyPair generate() throws Exception {
        return KeyPairGenerator.getInstance("Frodo", "BCPQC").generateKeyPair();
    }
}
