import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GostCtrWrap {
    static void lw(String name, org.bouncycastle.crypto.BlockCipher eng, int keyLen) {
        int bs = eng.getBlockSize();
        G3413CTRBlockCipher c = new G3413CTRBlockCipher(eng);
        c.init(true, new ParametersWithIV(new KeyParameter(new byte[keyLen]), new byte[bs / 2]));
        byte[] ks = new byte[bs * 300];
        c.processBytes(new byte[ks.length], 0, ks.length, ks, 0); // zero plaintext => keystream
        boolean rep = Arrays.equals(Arrays.copyOfRange(ks, 0, bs), Arrays.copyOfRange(ks, 256 * bs, 257 * bs));
        System.out.println("lightweight " + c.getAlgorithmName() + " blockSize=" + bs + " keystream block[256]==block[0]: " + rep);
    }
    public static void main(String[] a) throws Exception {
        lw("Kuznyechik", new GOST3412_2015Engine(), 32);
        lw("GOST28147", new GOST28147Engine(), 32);
        Cipher ci = Cipher.getInstance("GOST3412-2015/CTR/NoPadding", new BouncyCastleProvider());
        ci.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "GOST3412-2015"), new IvParameterSpec(new byte[8]));
        byte[] ks = ci.doFinal(new byte[16 * 300]);
        boolean rep = Arrays.equals(Arrays.copyOfRange(ks, 0, 16), Arrays.copyOfRange(ks, 256 * 16, 257 * 16));
        System.out.println("JCE GOST3412-2015/CTR/NoPadding (BC) impl=" + ci.getProvider().getName() + " keystream block[256]==block[0]: " + rep);
        try {
            Cipher g = Cipher.getInstance("GOST28147/CTR/NoPadding", new BouncyCastleProvider());
            g.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "GOST28147"), new IvParameterSpec(new byte[8]));
            byte[] k2 = g.doFinal(new byte[8 * 300]);
            System.out.println("JCE GOST28147/CTR/NoPadding (BC, SICBlockCipher) block[256]==block[0]: " + Arrays.equals(Arrays.copyOfRange(k2, 0, 8), Arrays.copyOfRange(k2, 256 * 8, 257 * 8)));
            Cipher g2 = Cipher.getInstance("GOST28147/GOFB/NoPadding", new BouncyCastleProvider());
            g2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "GOST28147"), new IvParameterSpec(new byte[8]));
            byte[] k3 = g2.doFinal(new byte[8 * 300]);
            System.out.println("JCE GOST28147/GOFB/NoPadding (BC, GOFBBlockCipher) block[256]==block[0]: " + Arrays.equals(Arrays.copyOfRange(k3, 0, 8), Arrays.copyOfRange(k3, 256 * 8, 257 * 8)));
        } catch (Exception e) { System.out.println("other modes: " + e); }
    }
}
