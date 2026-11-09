package org.apache.catalina.authenticator;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.connector.Request;

import java.util.List;

/** Fixture stub with Tomcat 11.0.24 names/descriptors. */
public class DigestAuthenticator extends AuthenticatorBase {
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) {
        DigestInfo info = new DigestInfo();
        return info.validate(request, List.of());
    }

    public static class DigestInfo {
        private final NonceInfo nonce = new NonceInfo(100);

        public boolean validate(Request request, List<?> cache) {
            return nonce.nonceCountValid(1L);
        }
    }

    public static class NonceInfo {
        private final boolean[] seen;
        private int count;

        public NonceInfo(int windowSize) {
            seen = new boolean[windowSize];
        }

        public synchronized boolean nonceCountValid(long nonceCount) {
            int checkIndex = (int) (nonceCount % seen.length);
            if (seen[checkIndex]) {
                return false;
            }
            seen[checkIndex] = true;
            seen[count % seen.length] = false; // 11.0.24 order (fixed version increments first)
            count++;
            return true;
        }
    }
}
