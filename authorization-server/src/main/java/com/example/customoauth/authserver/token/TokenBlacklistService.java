package com.example.customoauth.authserver.token;
import org.springframework.data.redis.core.StringRedisTemplate; import org.springframework.stereotype.Service; import java.time.Duration;
@Service public class TokenBlacklistService {
  private final StringRedisTemplate redis; public TokenBlacklistService(StringRedisTemplate r){ this.redis=r; }
  public void blacklist(String jti, long ttl){ if(jti==null || jti.isBlank()) return; redis.opsForValue().set("blacklist:access:"+jti,"1", Duration.ofSeconds(ttl)); }
}
