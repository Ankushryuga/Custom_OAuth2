//// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
//package com.example.authorizationserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//@EnableWebSecurity
//public class AuthorizationServerSecurityConfig {
//
//    @Bean
//    @Order(1)
//    // authorization-server/.../AuthorizationServerSecurityConfig.java
//    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        var as = http.getConfigurer(org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class);
//        var endpoints = as.getEndpointsMatcher();
//        http.securityMatcher(endpoints);
//
//        // ⬇️ if not logged in, send to /login instead of whitelabel/500
//        http.exceptionHandling(ex -> ex
//                .authenticationEntryPoint(new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"))
//        );
//
//        as.oidc(Customizer.withDefaults());
//        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**","/.well-known/**"));
//        return http.build();
//    }
//
////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////        // Register all OAuth2/OIDC endpoints and their security
////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////
////        // Keep OIDC enabled; do NOT enable SAS built-in DCR since you have your own controller
////        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
////                .oidc(Customizer.withDefaults());
////
////        // Resource-server JWT for endpoints like revoke if needed
////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////
////        // CSRF: only ignore oauth2 endpoints here; /connect/register will be handled in @Order(2)
////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
////
////        return http.build();
////    }
//
//    @Bean
//    @Order(2)
//    SecurityFilterChain application(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(reg -> reg
//                        // ✅ Permit your custom DCR endpoint here (not in @Order(1))
//                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//                        .requestMatchers("/login", "/error", "/actuator/**").permitAll()
//                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults())
//                .httpBasic(Customizer.withDefaults())
//                // ✅ Also ignore CSRF for your DCR endpoint here
//                .csrf(csrf -> csrf.ignoringRequestMatchers("/connect/register", "/admin/clients"));
//
//        return http.build();
//    }
//
//    @Bean
//    AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://localhost:9000")
//                .build();
//    }
//}


// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class AuthorizationServerSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
        // Register all OAuth2/OIDC endpoints and their default security (includes anyRequest().authenticated())
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Scope this chain to the AS endpoints
        var as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
        http.securityMatcher(as.getEndpointsMatcher());

        // If not logged in, send to /login
        http.exceptionHandling(ex ->
                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );

        // Enable OIDC
        as.oidc(Customizer.withDefaults());

        // Resource server (JWT) for endpoints like revoke/introspect if needed
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        // Enable CORS processing on this chain (actual policy provided by CorsConfigurationSource bean)
        http.cors(Customizer.withDefaults());

        // Ignore CSRF for core OAuth2/OIDC endpoints
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain application(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(reg -> reg
                        // Allow CORS preflight for app endpoints
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Your custom DCR endpoint is open (controller validates initial token)
                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()

                        // Public pages
                        .requestMatchers("/login", "/error", "/actuator/**").permitAll()

                        // Admin API
                        .requestMatchers("/admin/clients").hasRole("ADMIN")

                        // Everything else requires auth
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())

                // Enable CORS on this chain
                .cors(Customizer.withDefaults())

                // Ignore CSRF for JSON endpoints you call from the React app
                .csrf(csrf -> csrf.ignoringRequestMatchers("/connect/register", "/admin/clients"));

        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }
}
