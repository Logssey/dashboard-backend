import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.PKIXNameConstraintValidator;
import org.bouncycastle.asn1.x509.NameConstraintValidatorException;

public class NcTrailingDot {
    static String excluded(int tag, String constraint, String name) {
        PKIXNameConstraintValidator v = new PKIXNameConstraintValidator();
        v.addExcludedSubtree(new GeneralSubtree(new GeneralName(tag, constraint)));
        try { v.checkExcluded(new GeneralName(tag, name)); return "ACCEPTED (not excluded)"; }
        catch (NameConstraintValidatorException e) { return "REJECTED: " + e.getMessage(); }
    }
    public static void main(String[] a) {
        String ver = org.bouncycastle.jce.provider.BouncyCastleProvider.class.getPackage().getImplementationVersion();
        System.out.println("bcprov impl version: " + ver);
        String[][] cases = {
            {"rfc822Name", "bank.com", "user@bank.com"},
            {"rfc822Name", "bank.com", "user@bank.com."},
            {"rfc822Name", ".bank.com", "user@mail.bank.com"},
            {"rfc822Name", ".bank.com", "user@mail.bank.com."},
            {"uniformResourceIdentifier", "competitor.example", "https://competitor.example/"},
            {"uniformResourceIdentifier", "competitor.example", "https://competitor.example./"},
            {"dNSName", "bank.com", "www.bank.com"},
            {"dNSName", "bank.com", "www.bank.com."},
        };
        for (String[] c : cases) {
            int tag = c[0].equals("rfc822Name") ? GeneralName.rfc822Name : c[0].equals("dNSName") ? GeneralName.dNSName : GeneralName.uniformResourceIdentifier;
            System.out.printf("%-26s excluded=%-20s name=%-32s -> %s%n", c[0], c[1], c[2], excluded(tag, c[1], c[2]));
        }
    }
}
