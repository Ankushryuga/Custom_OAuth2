//package com.example.customoauth.resourceserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rsSecurity(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        // require a valid access token for the API
//                        .requestMatchers("/api/hello").authenticated()
//                        // optionally enforce scope:
//                        // .requestMatchers("/api/hello").hasAuthority("SCOPE_openid")
//                        .anyRequest().denyAll()
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//        return http.build();
//    }
//}


//package com.example.customoauth.resourceserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rsSecurity(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()  // no scope requirement
//                        .anyRequest().denyAll())
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//        return http.build();
//    }
//}

//package com.example.customoauth.resourceserver.config;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.AuthenticationException; // <-- correct type
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rs(HttpSecurity http) throws Exception {
//        var jwtAuthConverter = new JwtAuthenticationConverter();
//
//        http
//                .authorizeHttpRequests(a -> a
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()
//                        .anyRequest().denyAll()
//                )
//                .oauth2ResourceServer(o -> o
//                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
//                        .authenticationEntryPoint(
//                                (HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
//                                    res.setStatus(401);
//                                    res.setContentType("text/plain");
//                                    res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
//                                }
//                        )
//                );
//
//        return http.build();
//    }
//}
//


//package com.example.customoauth.resourceserver.config;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rs(HttpSecurity http) throws Exception {
//        var jwtAuthConverter = new JwtAuthenticationConverter(); // no extra authorities mapping needed
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()
//                        .anyRequest().denyAll()
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
//                        .authenticationEntryPoint(
//                                (HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
//                                    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                                    res.setContentType("text/plain");
//                                    res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
//                                }
//                        )
//                );
//
//        return http.build();
//    }
//}


//package com.example.customoauth.resourceserver.config;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
//import org.springframework.security.oauth2.core.OAuth2TokenValidator;
//import org.springframework.security.oauth2.jwt.*;
//import org.springframework.security.web.SecurityFilterChain;
//
//import java.time.Duration;

//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rs(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(a -> a
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()
//                        .anyRequest().denyAll()
//                )
//                .oauth2ResourceServer(o -> o
//                        .jwt(Customizer.withDefaults())
//                        .authenticationEntryPoint((HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
//                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                            res.setContentType("text/plain");
//                            res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
//                        })
//                );
//
//        return http.build();
//    }
//
//    /**
//     * Single JwtDecoder bean built from issuer, with small clock skew tolerance.
//     * Ensure you do NOT have any other JwtDecoder beans.
//     */
//    @Bean
//    JwtDecoder jwtDecoder() {
//        String issuer = "http://localhost:9000";
//        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
//
//        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
//        OAuth2TokenValidator<Jwt> withSkew = new JwtTimestampValidator(Duration.ofSeconds(60));
//        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, withSkew));
//
//        return decoder;
//    }
//}



//@Configuration
//public class ResourceServerSecurityConfig {
//    @Bean
//    SecurityFilterChain rs(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(a -> a
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()
//                        .anyRequest().denyAll()
//                )
//                .oauth2ResourceServer(o -> o
//                        .jwt(Customizer.withDefaults())
//                        .authenticationEntryPoint((HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
//                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                            res.setContentType("text/plain");
//                            res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
//                        })
//                );
//        return http.build();
//    }
//}


//package com.example.customoauth.resourceserver.config;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.JwtDecoders;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
//import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class ResourceServerSecurityConfig {
//
//    @Bean
//    SecurityFilterChain rs(HttpSecurity http) throws Exception {
//        // Dynamically resolve the issuer from token 'iss' and create a decoder for it
//        JwtIssuerAuthenticationManagerResolver resolver =
//                new JwtIssuerAuthenticationManagerResolver(issuer -> authenticationManagerFor(issuer));
//
//        http
//                .authorizeHttpRequests(a -> a
//                        .requestMatchers("/", "/actuator/health").permitAll()
//                        .requestMatchers("/api/hello").authenticated()
//                        .anyRequest().denyAll())
//                .oauth2ResourceServer(o -> o
//                        .authenticationManagerResolver(resolver)
//                        .authenticationEntryPoint((HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
//                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                            res.setContentType("text/plain");
//                            res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
//                        })
//                );
//
//        return http.build();
//    }
//
//    // Build an AuthenticationManager (provider) for a given issuer
//    private AuthenticationManager authenticationManagerFor(String issuer) {
//        JwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer); // uses OIDC discovery to fetch JWKS
//        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
//        provider.setJwtAuthenticationConverter(new JwtAuthenticationConverter());
//        return new ProviderManager(provider);
//    }
//}



package com.example.customoauth.resourceserver.config;

import com.example.customoauth.resourceserver.security.TenantAuthenticationManagerResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ResourceServerSecurityConfig {

    // Shared JWKS served by your Authorization Server (same keys for all tenants)
    private static final String ROOT_JWKS_URI = "http://localhost:9000/oauth2/jwks";
    // All tenant issuers must start with this prefix:
    private static final String TENANT_ISSUER_PREFIX = "http://localhost:9000/tenants/";

    @Bean
    SecurityFilterChain rs(HttpSecurity http) throws Exception {
        var resolver = new TenantAuthenticationManagerResolver(ROOT_JWKS_URI, TENANT_ISSUER_PREFIX);

        http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/", "/actuator/health").permitAll()
                        .requestMatchers("/api/hello").authenticated()
                        .anyRequest().denyAll()
                )
                .oauth2ResourceServer(o -> o
                        .authenticationManagerResolver(resolver)
                        .authenticationEntryPoint((HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            res.setContentType("text/plain");
                            res.getWriter().println("Resource Server rejected token: " + ex.getMessage());
                        })
                );

        return http.build();
    }
}
