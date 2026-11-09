import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class NcCertPath {
    static final AlgorithmIdentifier SIGALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2")); // ecdsa-with-SHA256
    static long serial = 1;
    static X509Certificate mk(String subj, PublicKey pub, String issuer, PrivateKey signer, Extensions ext) throws Exception {
        V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
        g.setSerialNumber(new ASN1Integer(BigInteger.valueOf(serial++)));
        g.setIssuer(new X500Name(issuer)); g.setSubject(new X500Name(subj));
        g.setStartDate(new Time(new Date(System.currentTimeMillis() - 3600_000L)));
        g.setEndDate(new Time(new Date(System.currentTimeMillis() + 86400_000L)));
        g.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pub.getEncoded()));
        g.setSignature(SIGALG); g.setExtensions(ext);
        TBSCertificate tbs = g.generateTBSCertificate();
        Signature s = Signature.getInstance("SHA256withECDSA", "SunEC"); s.initSign(signer); s.update(tbs.getEncoded(ASN1Encoding.DER));
        byte[] der = new DERSequence(new ASN1Encodable[]{tbs, SIGALG, new DERBitString(s.sign())}).getEncoded(ASN1Encoding.DER);
        return (X509Certificate) CertificateFactory.getInstance("X.509", "SUN").generateCertificate(new ByteArrayInputStream(der));
    }
    static Extensions caExt(NameConstraints nc) throws Exception {
        ExtensionsGenerator eg = new ExtensionsGenerator();
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        if (nc != null) eg.addExtension(org.bouncycastle.asn1.x509.Extension.nameConstraints, true, nc);
        return eg.generate();
    }
    static Extensions eeExt(GeneralName san) throws Exception {
        ExtensionsGenerator eg = new ExtensionsGenerator();
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, new GeneralNames(san));
        return eg.generate();
    }
    static String validate(String prov, CertPath cp, PKIXParameters p) {
        try { CertPathValidator v = prov == null ? CertPathValidator.getInstance("PKIX") : CertPathValidator.getInstance("PKIX", prov);
              v.validate(cp, p); return "VALID (provider=" + v.getProvider().getName() + ")"; }
        catch (Exception e) { return "REJECTED: " + e.getMessage(); }
    }
    public static void main(String[] a) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "SunEC"); kpg.initialize(256);
        KeyPair root = kpg.generateKeyPair(), inter = kpg.generateKeyPair(), ee = kpg.generateKeyPair();
        X509Certificate rootC = mk("CN=Root", root.getPublic(), "CN=Root", root.getPrivate(), caExt(null));
        GeneralSubtree[] excl = { new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")),
                                  new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "competitor.example")) };
        X509Certificate interC = mk("CN=Constrained Sub-CA", inter.getPublic(), "CN=Root", root.getPrivate(), caExt(new NameConstraints(null, excl)));
        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(rootC, null)));
        params.setRevocationEnabled(false);
        Security.addProvider(new BouncyCastleProvider()); // appended at the end
        System.out.println("default PKIX CertPathValidator provider with BC appended: " + CertPathValidator.getInstance("PKIX").getProvider().getName());
        String[][] sans = {{"rfc822", "user@bank.com"}, {"rfc822", "user@bank.com."}, {"uri", "https://competitor.example/"}, {"uri", "https://competitor.example./"}};
        for (String[] s : sans) {
            int tag = s[0].equals("rfc822") ? GeneralName.rfc822Name : GeneralName.uniformResourceIdentifier;
            X509Certificate eeC = mk("CN=leaf", ee.getPublic(), "CN=Constrained Sub-CA", inter.getPrivate(), eeExt(new GeneralName(tag, s[1])));
            CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList(eeC, interC));
            System.out.printf("SAN %-6s %-30s BC: %-45s | SUN: %s%n", s[0], s[1], validate("BC", cp, params), validate("SUN", cp, params));
        }
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("default PKIX CertPathValidator provider with BC inserted at 1: " + CertPathValidator.getInstance("PKIX").getProvider().getName()
            + " / CertPathBuilder: " + CertPathBuilder.getInstance("PKIX").getProvider().getName()
            + " / X.509 CertificateFactory: " + CertificateFactory.getInstance("X.509").getProvider().getName());
    }
}
