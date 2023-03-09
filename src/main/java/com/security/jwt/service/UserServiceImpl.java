package com.security.jwt.service;

import org.springframework.http.ResponseEntity;

import com.security.jwt.model.User;

public interface UserServiceImpl {
    String authenticate();
    User saverUser (User user) ;
}
