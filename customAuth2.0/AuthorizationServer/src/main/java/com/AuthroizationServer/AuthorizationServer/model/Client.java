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
}
