package com.example.risky;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/** CVE-2026-13506 positive control: lazily parsed ASN.1 from the caller, walked to the end. */
public class Asn1Lazy {
    public int countElements(byte[] der) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der, true)) {
            ASN1Primitive obj = in.readObject();
            int n = 0;
            if (obj instanceof ASN1Sequence seq) {
                for (Enumeration<?> e = seq.getObjects(); e.hasMoreElements(); e.nextElement()) n++;
            }
            return n;
        }
    }
}
