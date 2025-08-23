package com.AuthroizationServer.AuthorizationServer.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

@Entity
@Table(name="users")
@Getter
@Setter
public class User implements UserDetails {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean enabled= true;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name="user_roles", joinColumns = @JoinColumn(name="user_id"), inverseJoinColumns = @JoinColumn(name="role_id"))
    private Set<Role> authorities;

    //UserDetails
    @Override public boolean isAccountNonExpired(){ return true;}
    @Override public boolean isAccountNonLocked(){ return true; }
    @Override public boolean isCredentialsNonExpired(){ return true;}
    @Override public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }

    @Override public String getUsername(){return username;}
    @Override public String getPassword(){return password;}
    @Override public boolean isEnabled(){return enabled;}
}
