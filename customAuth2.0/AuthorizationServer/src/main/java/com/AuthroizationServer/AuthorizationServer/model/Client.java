package com.AuthroizationServer.AuthorizationServer.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "clients")
@Getter
@Setter
public class Client {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name="client_secret", nullable = false)
    private String clientSecret;

    @Column(name="redirect_uri", nullable = false)
    private String redirectUri;

    /**
     * Comma‑separated list of OAuth2 scopes that this client is allowed to request.  This
     * corresponds to the {@code scopes} column in the {@code clients} table created by Flyway.
     */
    @Column(name = "scopes")
    private String scopes;

    /**
     * Comma‑separated list of authorization grant types (e.g. {@code authorization_code},
     * {@code client_credentials}, {@code refresh_token}) configured for this client.
     */
    @Column(name = "grant_types")
    private String grantTypes;


    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

    public String getScopes() { return scopes; }
    public void setScopes(String scopes) { this.scopes = scopes; }

    public String getGrantTypes() { return grantTypes; }
    public void setGrantTypes(String grantTypes) { this.grantTypes = grantTypes; }

}
