package com.example.customoauth.resourceserver.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Resolves an AuthenticationManager based on the tenant issuer found in the JWT "iss" claim.
 * Signature is verified using a single JWKS (shared by all tenants).
 */
public class TenantAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final String jwkSetUri;          // e.g., http://localhost:9000/oauth2/jwks
    private final String issuerPrefix;       // e.g., http://localhost:9000/tenants/
    private final DefaultBearerTokenResolver tokenResolver = new DefaultBearerTokenResolver();

    public TenantAuthenticationManagerResolver(String jwkSetUri, String issuerPrefix) {
        Assert.hasText(jwkSetUri, "jwkSetUri must not be empty");
        Assert.hasText(issuerPrefix, "issuerPrefix must not be empty");
        this.jwkSetUri = jwkSetUri;
        this.issuerPrefix = issuerPrefix.endsWith("/") ? issuerPrefix : issuerPrefix + "/";
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        String token = tokenResolver.resolve(request);
        if (token == null) {
            // No bearer token -> let RS entry point handle 401
            return authentication -> { throw new JwtException("Missing bearer token"); };
        }

        String issuer = extractIssuerUnsafe(token);
        if (issuer == null || !issuer.startsWith(this.issuerPrefix)) {
            String msg = "Untrusted or missing issuer in token: " + issuer;
            return authentication -> { throw new JwtException(msg); };
        }

        // Build a decoder that verifies signature using the shared JWKS
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();

        // Allow small clock skew + require the token's `iss` to equal the extracted issuer
        OAuth2TokenValidator<Jwt> timestamps = new JwtTimestampValidator(Duration.ofSeconds(60));
        OAuth2TokenValidator<Jwt> issuerExact = jwt -> {
            String iss = jwt.getIssuer() != null ? jwt.getIssuer().toString() : null;
            if (issuer.equals(iss)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token",
                            "Issuer mismatch. Expected " + issuer + " but was " + iss, null));
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamps, issuerExact));

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(new JwtAuthenticationConverter());
        return new ProviderManager(provider);
    }

    /**
     * Extract the "iss" claim by decoding the JWT payload without verifying.
     * This is safe here because we only use it to choose the proper validator/decoder;
     * the actual signature verification happens later via NimbusJwtDecoder.
     */
    @SuppressWarnings("unchecked")
    private String extractIssuerUnsafe(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            // Fast minimal JSON parse to avoid adding a full mapper:
            // Look for "iss":"...". For robustness you can swap to Jackson if you prefer.
            int idx = payloadJson.indexOf("\"iss\"");
            if (idx < 0) return null;
            int colon = payloadJson.indexOf(':', idx);
            if (colon < 0) return null;
            int firstQuote = payloadJson.indexOf('"', colon + 1);
            int secondQuote = payloadJson.indexOf('"', firstQuote + 1);
            if (firstQuote < 0 || secondQuote < 0) return null;
            return payloadJson.substring(firstQuote + 1, secondQuote);
        } catch (Exception e) {
            return null;
        }
    }
}
