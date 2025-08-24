package com.AuthroizationServer.AuthorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // You can also use DelegatingPasswordEncoder if you want multiple encoding types
//        String encoded = new BCryptPasswordEncoder().encode("password");
//        System.out.println(encoded);
//        return new BCryptPasswordEncoder();
//        return org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();

    }
}
