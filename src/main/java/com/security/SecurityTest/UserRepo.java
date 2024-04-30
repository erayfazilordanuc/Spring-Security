package com.security.SecurityTest;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<SecureUser, Integer> {
    public SecureUser findByUsername(String username);
    public SecureUser findByEmail(String email);
}
