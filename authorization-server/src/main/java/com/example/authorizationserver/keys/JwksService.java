package com.example.authorizationserver.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.UUID;

@Service
public class JwksService {

    @Value("${auth.jwks.path:./data/jwks.json}")
    private String jwksPath;

    public JWKSet loadOrCreateJwkSet() {
        try {
            File f = new File(jwksPath);
            if (f.exists()) {
                try (FileReader fr = new FileReader(f)) {
                    StringBuilder sb = new StringBuilder();
                    int c; while ((c = fr.read()) != -1) sb.append((char) c);
                    Map<String, Object> json = JSONObjectUtils.parse(sb.toString());
                    JWKSet set = JWKSet.parse(json);
                    // If all keys are public-only, regenerate so we have private material to sign with
                    boolean hasPrivate = set.getKeys().stream().anyMatch(JWK::isPrivate);
                    if (!hasPrivate) {
                        set = new JWKSet(generateRsa());
                        try (FileWriter fw = new FileWriter(f)) {
                            fw.write(JSONObjectUtils.toJSONString(set.toJSONObject(true)));
                        }
                    }
                    return set;
                }
            } else {
                f.getParentFile().mkdirs();
                JWKSet set = new JWKSet(generateRsa());
                try (FileWriter fw = new FileWriter(f)) {
                    fw.write(JSONObjectUtils.toJSONString(set.toJSONObject(true))); // include private params
                }
                return set;
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load/create JWKS", e);
        }
    }

    private RSAKey generateRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic())
                .privateKey(kp.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
