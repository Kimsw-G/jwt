package com.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.jwt.config.jwt.JwtProperties;
import com.security.jwt.model.User;
import com.security.jwt.repo.UserRepository;

@Service
public class UserService implements UserServiceImpl{
    
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtProperties jwtProperties;
    @Override
    public String authenticate() {
        return null;
    }
    @Override
    public User saverUser(User user) {
        return userRepository.save(user);
    }


    

}
