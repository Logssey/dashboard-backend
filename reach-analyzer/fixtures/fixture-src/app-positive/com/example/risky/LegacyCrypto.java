package com.example.risky;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.springframework.stereotype.Service;

/** Uses the vulnerable GOST R 34.13-2015 CTR mode directly (CVE-2025-14813). */
@Service
public class LegacyCrypto {
    public byte[] gostEncrypt(byte[] key, byte[] iv, byte[] data) {
        G3413CTRBlockCipher cipher = new G3413CTRBlockCipher(new GOST3412_2015Engine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[data.length];
        cipher.processBytes(data, 0, data.length, out, 0);
        return out;
    }
}
