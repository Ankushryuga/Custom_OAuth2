package com.customoauth2.customAuth20.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests(auth->auth.requestMatchers("/", "/public").permitAll().anyRequest().authenticated())
                .oauth2Login(oauth2->oauth2.loginPage("/oauth2/authorization/client-app")
                )
                .logout(logout->logout.logoutSuccessUrl("/").permitAll()
                );

        return http.build();
    }
}
