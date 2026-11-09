package com.example.risky;

import java.util.Collection;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.util.LDAPStoreHelper;

/** CVE-2026-0636 positive control: BC LDAP store searched with a subject from the caller. */
public class LdapCertLookup {
    public Collection<?> bySubject(String subjectDn) throws Exception {
        LDAPStoreHelper helper = new LDAPStoreHelper(new X509LDAPCertStoreParameters.Builder("ldap://directory.example", "o=example").build());
        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(new X500Principal(subjectDn));
        return helper.getUserCertificates(selector);
    }
}
