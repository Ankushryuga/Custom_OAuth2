package com.example.resourceserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
// ✅ correct package:
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
public class SecurityConfig {

    private final StringRedisTemplate redis;

    public SecurityConfig(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Bean
    SecurityFilterChain rs(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(reg -> reg
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/api/**").hasAuthority("SCOPE_api.read")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        // after the Bearer token has been parsed & authenticated
        http.addFilterAfter(new RevokedJtiFilter(redis), BearerTokenAuthenticationFilter.class);

        return http.build();
    }

    static class RevokedJtiFilter extends OncePerRequestFilter {
        private final StringRedisTemplate redis;
        RevokedJtiFilter(StringRedisTemplate redis) { this.redis = redis; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth instanceof JwtAuthenticationToken jwtAuth) {
                String jti = jwtAuth.getToken().getId();
                String val = redis.opsForValue().get("revoked:" + jti);
                if (val != null) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("token revoked");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
