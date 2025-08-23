package com.AuthroizationServer.AuthorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain appSecurity(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(auth->auth.requestMatchers("/.well-known/**").permitAll().anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // customUserDetailsService is auto-wired by Spring Security as a UserDetailsService bean.
}
