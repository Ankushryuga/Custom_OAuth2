package com.example.authorizationserver.revoke;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;

@RestController
public class RevocationController {

    private final JwtDecoder jwtDecoder;
    private final StringRedisTemplate redis;

    public RevocationController(JwtDecoder jwtDecoder, StringRedisTemplate redis) {
        this.jwtDecoder = jwtDecoder;
        this.redis = redis;
    }

    @GetMapping("/revoke")
    public ResponseEntity<?> revoke(@RequestHeader(name = "Authorization", required = false) String auth) {
        if (!StringUtils.hasText(auth) || !auth.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing Bearer token");
        }
        String token = auth.substring("Bearer ".length()).trim();
        Jwt jwt = jwtDecoder.decode(token);
        String jti = jwt.getId();
        Instant exp = jwt.getExpiresAt();
        long ttl = 600;
        if (exp != null) {
            long seconds = exp.getEpochSecond() - Instant.now().getEpochSecond();
            ttl = Math.max(1, seconds);
        }
        redis.opsForValue().set("revoked:" + jti, "1", Duration.ofSeconds(ttl));
        return ResponseEntity.ok("revoked");
    }
}
