//package com.example.authserver.support;
//
//import com.nimbusds.jose.jwk.JWK;
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.JWKSelector;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import com.nimbusds.jose.util.JSONObjectUtils;
//import java.io.File;
//import java.io.FileWriter;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.Date;
//import java.util.UUID;
//
//public class FileBackedJwks implements JWKSource<SecurityContext> {
//  private final File dir;
//  public FileBackedJwks(String path) {
//    this.dir = new File(path);
//    if (!dir.exists()) dir.mkdirs();
//    ensureKey();
//  }
//  private synchronized void ensureKey() {
//    File f = new File(dir, "jwks.json");
//    if (f.exists()) return;
//    try {
//      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//      kpg.initialize(2048);
//      KeyPair kp = kpg.generateKeyPair();
//      RSAKey rsa = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
//        .privateKey((RSAPrivateKey) kp.getPrivate())
//        .keyID(UUID.randomUUID().toString())
//        .issueTime(new Date())
//        .build();
//      JWKSet set = new JWKSet(rsa);
//      try (FileWriter fw = new FileWriter(f)) {
//        fw.write(JSONObjectUtils.toJSONString(set.toJSONObject(true)));
//      }
//    } catch (Exception e) {
//      throw new RuntimeException(e);
//    }
//  }
//  private JWKSet read() {
//    File f = new File(dir, "jwks.json");
//    try {
//      String json = Files.readString(Path.of(f.getAbsolutePath()));
//      return JWKSet.parse(JSONObjectUtils.parse(json));
//    } catch (Exception e) {
//      throw new RuntimeException(e);
//    }
//  }
//  @Override
//  public java.util.List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
//    return jwkSelector.select(read());
//  }
//}

package com.example.authserver.support;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Loads {dir}/jwks.json. If missing or it has no PRIVATE signing key,
 * generates a new RSA key (includes private params), persists it, and serves it.
 */
public final class FileBackedJwks implements JWKSource<SecurityContext> {

  private final Path jwksFile;
  private volatile ImmutableJWKSet<SecurityContext> delegate;

  public FileBackedJwks(String dir) {
    try {
      Path base = Paths.get(dir).toAbsolutePath().normalize();
      Files.createDirectories(base);
      this.jwksFile = base.resolve("jwks.json");
      JWKSet set = ensureJwks();
      this.delegate = new ImmutableJWKSet<>(set);
      System.out.println("[JWKS] Using file: " + jwksFile);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to initialize JWKS", e);
    }
  }

  @Override
  public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
    try {
      return delegate.get(jwkSelector, context);
    } catch (Exception e) {
      // Keep the interface clean across Nimbus versions
      throw new RuntimeException("JWKS selection failed", e);
    }
  }

  private JWKSet ensureJwks() throws IOException {
    if (Files.exists(jwksFile)) {
      try {
        String json = Files.readString(jwksFile, StandardCharsets.UTF_8);
        JWKSet set = JWKSet.parse(json);
        if (hasPrivateSigner(set)) {
          System.out.println("[JWKS] Loaded existing JWKS with private signing key");
          return set;
        } else {
          System.out.println("[JWKS] JWKS present but no PRIVATE signing key — generating one…");
          return writeNew(set);
        }
      } catch (ParseException e) {
        System.out.println("[JWKS] Corrupt JWKS — regenerating: " + e.getMessage());
        return writeNew(null);
      }
    } else {
      System.out.println("[JWKS] No JWKS — generating a new one…");
      return writeNew(null);
    }
  }

  private static boolean hasPrivateSigner(JWKSet set) {
    for (JWK j : set.getKeys()) {
      if (j instanceof RSAKey rsa) {
        if (KeyUse.SIGNATURE.equals(rsa.getKeyUse()) && rsa.isPrivate()) {
          return true;
        }
      }
    }
    return false;
  }

  private JWKSet writeNew(JWKSet existing) throws IOException {
    try {
      RSAKey rsa = new RSAKeyGenerator(2048)
              .keyUse(KeyUse.SIGNATURE)
              .keyIDFromThumbprint(true)
              .generate(); // includes private params

      List<JWK> keys = new ArrayList<>();
      keys.add(rsa);
      if (existing != null && !existing.getKeys().isEmpty()) {
        keys.addAll(existing.getKeys());
      }

      JWKSet newSet = new JWKSet(keys);

      Map<String, Object> json = newSet.toJSONObject(true); // include private params
      String text = JSONObjectUtils.toJSONString(json);
      Files.writeString(jwksFile, text, StandardCharsets.UTF_8,
              StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

      this.delegate = new ImmutableJWKSet<>(newSet);
      System.out.println("[JWKS] Generated & saved new RSA signing key (kid=" + rsa.getKeyID() + ")");
      return newSet;
    } catch (Exception e) {
      throw new IOException("Failed generating JWKS", e);
    }
  }
}
