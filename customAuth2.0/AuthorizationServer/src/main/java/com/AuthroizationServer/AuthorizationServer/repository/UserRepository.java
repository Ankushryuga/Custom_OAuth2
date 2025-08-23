package com.AuthroizationServer.AuthorizationServer.repository;

import com.AuthroizationServer.AuthorizationServer.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
