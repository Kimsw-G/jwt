package com.security.jwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.jwt.model.User;

public interface UserRepository extends JpaRepository<User,Long>{
    public User findByUsername(String username);
}
