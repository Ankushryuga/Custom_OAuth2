//package com.example.customoauth.client.config;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
//import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
//import org.springframework.web.reactive.function.client.WebClient;
//
//@Configuration
//public class WebClientOAuth2Config {
//
//    @Value("${app.resource.base-uri:http://localhost:8081}")
//    private String resourceBaseUri;
//
//    /**
//     * The AuthorizedClientManager drives acquiring/refreshing tokens for WebClient.
//     */
//    @Bean
//    OAuth2AuthorizedClientManager authorizedClientManager(
//            ClientRegistrationRepository registrations,
//            OAuth2AuthorizedClientService clientService) {
//
//        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
//                .authorizationCode()
//                .refreshToken()
//                .build();
//
//        var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, clientService);
//        manager.setAuthorizedClientProvider(provider);
//        return manager;
//    }
//
//    /**
//     * WebClient preconfigured to attach the Bearer token for registrationId "generic".
//     */
//    @Bean
//    WebClient resourceWebClient(OAuth2AuthorizedClientManager authorizedClientManager) {
//        var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
//        oauth2.setDefaultClientRegistrationId("generic"); // <- must match your "registration" id
//
//        return WebClient.builder()
//                .baseUrl(resourceBaseUri)
//                .filter(oauth2) // adds Authorization: Bearer <access_token>
//                .build();
//    }
//}



package com.example.customoauth.client.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientOAuth2Config {

    @Value("${app.resource.base-uri:http://localhost:8081}")
    private String resourceBaseUri;

    @Bean
    WebClient resourceWebClient(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        // Uses the session-backed AuthorizedClientRepository created by oauth2Login
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(registrations, authorizedClientRepository);

        // Attach the token for the CURRENT logged-in user automatically
        oauth2.setDefaultOAuth2AuthorizedClient(true);
        // And default to your registration id ("generic")
        oauth2.setDefaultClientRegistrationId("generic");

        return WebClient.builder()
                .baseUrl(resourceBaseUri)
                .apply(oauth2.oauth2Configuration())
                .build();
    }
}
