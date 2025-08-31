// authorization-server/src/main/java/com/example/authorizationserver/client/AdminDtos.java
package com.example.authorizationserver.client;

import java.util.List;

public class AdminDtos {
    public static class CreateClientRequest {
        public String clientId;
        public String clientName;
        public List<String> redirectUris;
        public List<String> grantTypes; // "authorization_code","refresh_token"
        public List<String> scopes;     // "openid","profile","email","api.read"
        public Boolean publicClient;    // true => PKCE, no secret
    }

    public static class CreatedClientResponse {
        public String client_id;
        public String client_secret; // null for public client
        public List<String> redirect_uris;
        public List<String> grant_types;
        public List<String> scopes;

        public CreatedClientResponse(String id, String secret,
                                     List<String> uris, List<String> grants, List<String> scopes) {
            this.client_id = id;
            this.client_secret = secret;
            this.redirect_uris = uris;
            this.grant_types = grants;
            this.scopes = scopes;
        }
    }
}
