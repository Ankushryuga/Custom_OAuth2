package com.example.customoauth.authserver.startup;
import org.springframework.boot.context.event.ApplicationReadyEvent; import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.core.AuthorizationGrantType; import org.springframework.security.oauth2.core.ClientAuthenticationMethod; import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient; import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings; import org.springframework.security.oauth2.server.authorization.settings.TokenSettings; import org.springframework.stereotype.Component;
import java.time.Duration; import java.util.UUID;
@Component public class DefaultClientLoader {
  private final RegisteredClientRepository repo; public DefaultClientLoader(RegisteredClientRepository r){ this.repo=r; }
  @EventListener(ApplicationReadyEvent.class) public void init(){
    String id = System.getenv().getOrDefault("DEFAULT_CLIENT_ID","web-pkce");
    String redirect = System.getenv().getOrDefault("DEFAULT_CLIENT_REDIRECT","http://localhost:8080/login/oauth2/code/generic");
    String post = System.getenv().getOrDefault("DEFAULT_CLIENT_POST_LOGOUT","http://localhost:8080/");
    String tenant = System.getenv().getOrDefault("DEFAULT_CLIENT_TENANT","acme");
    try{
      RegisteredClient rc = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(id)
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri(redirect).postLogoutRedirectUri(post).scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope(OidcScopes.EMAIL)
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(true).setting("tenant", tenant).build())
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).refreshTokenTimeToLive(Duration.ofDays(7)).reuseRefreshTokens(true).build())
        .build();
      repo.save(rc);
    }catch(Exception ignored){} }
}
