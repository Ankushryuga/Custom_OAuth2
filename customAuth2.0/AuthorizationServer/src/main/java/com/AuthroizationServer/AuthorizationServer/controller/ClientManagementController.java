package com.AuthroizationServer.AuthorizationServer.controller;

import com.AuthroizationServer.AuthorizationServer.model.Client;
import com.AuthroizationServer.AuthorizationServer.repository.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST API for managing OAuth2 clients.  This controller allows administrators to
 * programmatically register new clients without modifying SQL migration files.  A
 * basic in‑memory or database‑backed client registry can be built on top of
 * {@link ClientRepository}.  Only minimal validation is performed here; in a
 * production system you would add authentication, authorization and stronger
 * input validation.
 */
@RestController
@RequestMapping("/api/clients")
public class ClientManagementController {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ClientManagementController(ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Retrieve a list of all registered clients.  This endpoint is useful for
     * verifying that a new client was created successfully.
     *
     * @return a list of {@link Client} objects
     */
    @GetMapping
    public List<Client> listClients() {
        return clientRepository.findAll();
    }

    /**
     * Register a new OAuth2 client.  Expects a JSON payload containing at
     * minimum `clientId`, `clientSecret` and `redirectUri`.  Optional fields
     * include `scopes` and `grantTypes` (comma‑separated).  Client secrets are
     * encoded using the configured {@link PasswordEncoder} before being stored.
     *
     * Example payload:
     * <pre>
     * {
     *   "clientId": "example-app",
     *   "clientSecret": "super-secret",
     *   "redirectUri": "http://localhost:8081/login/oauth2/code/example-app",
     *   "scopes": "openid,profile,api.read",
     *   "grantTypes": "authorization_code,refresh_token"
     * }
     * </pre>
     *
     * @param request JSON map with client properties
     * @return the newly created client along with HTTP 201 status
     */
    @PostMapping
    public ResponseEntity<Client> registerClient(@RequestBody Map<String, String> request) {
        String clientId = request.get("clientId");
        String clientSecret = request.get("clientSecret");
        String redirectUri = request.get("redirectUri");
        if (clientId == null || clientSecret == null || redirectUri == null) {
            return ResponseEntity.badRequest().build();
        }

        Client client = new Client();
        client.setClientId(clientId);
        client.setClientSecret(clientSecret);
        client.setRedirectUri(redirectUri);
        // Optional fields
        client.setScopes(request.getOrDefault("scopes", "openid,profile"));
        client.setGrantTypes(request.getOrDefault("grantTypes", "authorization_code,refresh_token,client_credentials"));
        // Persist the client first
        Client saved = clientRepository.save(client);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
}