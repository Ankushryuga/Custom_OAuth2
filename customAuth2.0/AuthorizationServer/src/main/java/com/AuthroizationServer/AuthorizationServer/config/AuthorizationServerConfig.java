package com.AuthroizationServer.AuthorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@org.springframework.core.annotation.Order(1)
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Apply default security for Authorization Server
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Enable OpenID Connect 1.0
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // Restrict this filter chain to the OAuth2 and OIDC discovery endpoints only
        http.securityMatcher(new org.springframework.security.web.util.matcher.OrRequestMatcher(
                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/oauth2/**"),
                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/.well-known/**")
        ));

        // When an unauthenticated user attempts to access the authorization endpoint
        // the server should redirect them to the login page rather than returning 401.
        http.exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(
                        new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login")
                )
        );

        return http.build();
    }
    /**
     * Configure the issuer URL for the authorization server.  Without explicitly setting
     * the issuer Spring falls back to a default value which may not match the URL
     * expected by resource servers.  Setting the issuer ensures that the OIDC
     * discovery metadata and the `iss` claim in generated tokens are consistent with
     * the URI used by the resource server (see `ResourceServer/src/main/resources/application.yml`).
     *
     * @return a fully configured {@link AuthorizationServerSettings} instance
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // The issuer should reflect the externally exposed base URL of this authorization server.
        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    }
}
