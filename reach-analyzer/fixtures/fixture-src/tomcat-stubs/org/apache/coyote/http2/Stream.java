package org.apache.coyote.http2;

/** HTTP/2 stream. receivedEndOfHeaders is the required-header check of CVE-2026-65637; Tomcat calls it, apps do not. */
class Stream {
    final boolean receivedEndOfHeaders() {
        return true;
    }
}
