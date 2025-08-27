package com.example.customoauth.authserver.web;
import com.example.customoauth.authserver.token.TokenBlacklistService;
import org.springframework.http.ResponseEntity; import org.springframework.security.oauth2.jwt.*; import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*; import java.time.Instant;
@RestController @RequestMapping("/oauth2") public class RevocationController {
  private final JwtDecoder decoder; private final TokenBlacklistService blacklist;
  public RevocationController(JwtDecoder d, TokenBlacklistService b){ this.decoder=d; this.blacklist=b; }
  @PostMapping("/revoke") public ResponseEntity<?> revoke(@RequestParam("token") String token){
    try{ if(!StringUtils.hasText(token)) return ResponseEntity.ok().build();
      Jwt jwt = decoder.decode(token); String jti = jwt.getClaimAsString("jti");
      Instant exp = jwt.getExpiresAt(); long ttl = exp!=null? Math.max(0, exp.getEpochSecond()-Instant.now().getEpochSecond()) : 3600;
      blacklist.blacklist(jti, ttl);
    }catch(Exception ignored){} return ResponseEntity.ok().build(); }
}
