package com.example.customoauth.authserver.token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;
import java.util.Map; import java.util.UUID;
@Component public class TenantTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
  @Override public void customize(JwtEncodingContext ctx){
    ctx.getClaims().claim("jti", UUID.randomUUID().toString());
    Map<String,Object> s = ctx.getRegisteredClient().getClientSettings().getSettings();
    String tenant = s!=null && s.containsKey("tenant") ? String.valueOf(s.get("tenant")) : null;
    if(tenant!=null && !tenant.isBlank()){ ctx.getClaims().claim("tenant", tenant);
      if("access_token".equals(ctx.getTokenType().getValue())){
        String base = ctx.getAuthorizationServerContext().getIssuer();
        String iss = base.endsWith("/")? base+"tenants/"+tenant : base+"/tenants/"+tenant;
        JwtClaimsSet.Builder claims = ctx.getClaims(); claims.issuer(iss); } }
  }
}
