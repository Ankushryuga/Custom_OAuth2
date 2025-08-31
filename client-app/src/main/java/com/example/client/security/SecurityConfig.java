// client-app/src/main/java/com/example/client/security/SecurityConfig.java
package com.example.client.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    AuthorizationRequestRepository<OAuth2AuthorizationRequest> authzRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http,
                            AuthorizationRequestRepository<OAuth2AuthorizationRequest> repo) throws Exception {
        http.authorizeHttpRequests(reg -> reg
                        .requestMatchers("/", "/css/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(o -> o.authorizationEndpoint(e -> e.authorizationRequestRepository(repo)))
                .oauth2Client(Customizer.withDefaults())
                .logout(l -> l.logoutSuccessUrl("/").permitAll());
        return http.build();
    }
}
