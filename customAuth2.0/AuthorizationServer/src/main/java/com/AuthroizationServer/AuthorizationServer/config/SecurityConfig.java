package com.AuthroizationServer.AuthorizationServer.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import com.AuthroizationServer.AuthorizationServer.service.CustomUserDetailsService;

@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(CustomUserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    @org.springframework.core.annotation.Order(2)
    SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
        // This filter chain applies to all requests except the OAuth2 endpoints defined in the
        // AuthorizationServerConfig above.  Without setting a securityMatcher here,
        // Spring considers it as matching any request, which conflicts with the auth server chain.
        http.securityMatcher(new org.springframework.security.web.util.matcher.NegatedRequestMatcher(
                new org.springframework.security.web.util.matcher.OrRequestMatcher(
                        new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/oauth2/**"),
                        new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/.well-known/**")
                )));

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .authenticationProvider(authenticationProvider());

        return http.build();
    }


}
