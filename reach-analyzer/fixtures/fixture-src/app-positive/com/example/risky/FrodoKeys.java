package com.example.risky;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.springframework.stereotype.Service;

/** Uses FrodoKEM through the BC lightweight API (CVE-2026-5598): key generation samples the error matrix. */
@Service
public class FrodoKeys {
    public AsymmetricCipherKeyPair generate() {
        FrodoKeyPairGenerator generator = new FrodoKeyPairGenerator();
        generator.init(new FrodoKeyGenerationParameters(new SecureRandom(), FrodoParameters.frodokem640aes));
        return generator.generateKeyPair();
    }
}
