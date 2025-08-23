package com.customoauth2.customAuth20.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ResourceServerConfig {
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception{
//        http.authorizeHttpRequests(auth->auth.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated()).oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()));
        http.authorizeHttpRequests(auth->auth.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated()).oauth2ResourceServer(oauth->oauth.jwt(jwt->jwt.jwtAuthenticationConverter((jwtAuthenticationConverter()))));
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter scopesConverter=new JwtGrantedAuthoritiesConverter();
        scopesConverter.setAuthorityPrefix("SCOPE_");   // or "" for no prefix
        scopesConverter.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter jwtConverter=new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(scopesConverter);
        return jwtConverter;
    }
}
