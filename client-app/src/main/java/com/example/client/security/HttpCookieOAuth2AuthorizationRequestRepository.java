// client-app/src/main/java/com/example/client/security/HttpCookieOAuth2AuthorizationRequestRepository.java
package com.example.client.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;

import java.util.Base64;

public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String COOKIE_NAME = "OAUTH2_AUTHZ_REQ";

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        var cookie = CookieUtils.getCookie(request, COOKIE_NAME);
        if (cookie == null) return null;
        byte[] bytes = Base64.getUrlDecoder().decode(cookie.getValue());
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(bytes);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(response, COOKIE_NAME);
            return;
        }
        byte[] bytes = SerializationUtils.serialize(authorizationRequest);
        String val = Base64.getUrlEncoder().encodeToString(bytes);
        CookieUtils.addCookie(response, COOKIE_NAME, val, 180); // 3 min
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        var req = loadAuthorizationRequest(request);
        CookieUtils.deleteCookie(response, COOKIE_NAME);
        return req;
    }
}
