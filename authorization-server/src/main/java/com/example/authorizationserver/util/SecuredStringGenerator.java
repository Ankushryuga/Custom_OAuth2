// authorization-server/src/main/java/com/example/authorizationserver/util/SecuredStringGenerator.java
package com.example.authorizationserver.util;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecuredStringGenerator {
    private static final SecureRandom RNG = new SecureRandom();
    private SecuredStringGenerator() {}

    /** 48 random bytes -> ~64 char URL-safe string */
    public static String generateSecret() {
        byte[] buf = new byte[48];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** 24 random bytes -> ~32 char URL-safe id */
    public static String generateId() {
        byte[] buf = new byte[24];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
