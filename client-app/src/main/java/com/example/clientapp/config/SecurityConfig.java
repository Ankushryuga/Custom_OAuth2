package com.example.clientapp.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
public class SecurityConfig {
  @Bean
  SecurityFilterChain client(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth.requestMatchers("/", "/public/**").permitAll().anyRequest().authenticated())
        .oauth2Login(Customizer.withDefaults())
        .logout(l -> l.logoutSuccessUrl("/"));
    return http.build();
  }
}
