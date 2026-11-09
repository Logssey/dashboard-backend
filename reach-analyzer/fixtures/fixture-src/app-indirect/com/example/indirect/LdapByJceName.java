package com.example.indirect;

import java.security.cert.CertStore;
import java.security.cert.LDAPCertStoreParameters;
import java.util.Collection;

/**
 * CVE-2026-0636 through the JCE name only: JDK parameter class, provider "BC" picked by name, so the
 * provider table selects X509LDAPCertStoreSpi by reflection and no call edge or BC class reference
 * points at the vulnerable code. Must come out unknown, never unreachable.
 */
public class LdapByJceName {
    public Collection<?> all(String host, int port) throws Exception {
        CertStore store = CertStore.getInstance("LDAP", new LDAPCertStoreParameters(host, port), "BC");
        return store.getCertificates(null);
    }
}
