package com.example.risky;

import java.security.cert.CertPath;
import java.security.cert.PKIXParameters;
import org.bouncycastle.x509.PKIXCertPathReviewer;
import org.springframework.stereotype.Service;

/** Validates certificate paths with BouncyCastle's reviewer (name constraints, CVE-2026-8763). */
@Service
public class CertReview {
    public boolean review(CertPath path, PKIXParameters params) throws Exception {
        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer(path, params);
        return reviewer.isValidCertPath();
    }
}
