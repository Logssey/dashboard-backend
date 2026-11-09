package com.example.indirect;

import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.PKIXBuilderParameters;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

/** BC selected by JCE names, never by BC class names. */
@Service
public class JceCrypto {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] gostCtr(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("GOST3412-2015/CTR/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "GOST3412-2015"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public CertPathBuilderResult build(PKIXBuilderParameters params) throws Exception {
        return CertPathBuilder.getInstance("PKIX", "BC").build(params);
    }
}
