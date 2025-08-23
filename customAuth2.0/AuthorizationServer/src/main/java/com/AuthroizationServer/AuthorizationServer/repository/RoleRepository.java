package com.AuthroizationServer.AuthorizationServer.repository;

import com.AuthroizationServer.AuthorizationServer.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByAuthority(String authority);
}
