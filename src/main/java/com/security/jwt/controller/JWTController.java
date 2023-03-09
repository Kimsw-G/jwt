package com.security.jwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.config.jwt.JwtProperties;
import com.security.jwt.dto.UserDTO;
import com.security.jwt.model.User;
import com.security.jwt.repo.UserRepository;
import com.security.jwt.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@RestController
@RequiredArgsConstructor
@Log4j2
public class JwtController {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtProperties jwtProperties;

    @GetMapping(value = "/home")
    public String home() {
        String str = "<h1>home</h1><br>";
        str += """
                  <form action='/login' method='post' id='form'>
                  <input type='text' name='username' />
                  <input type='password' name='password' />
                  <button type='submit'>gogo</button>
                </form>
                <script>
                  const form = document.getElementById('form');

                  form.addEventListener('submit', (e) => {
                    e.preventDefault();
                    const formData = new FormData(form);
                    const payload = new URLSearchParams(formData);
                    const mybody = {
                        username: 'banana',
                        password: 'banana'
                    }
                    JSON.stringify(mybody)

                    console.log([...payload]);
                    console.log(mybody);
                    fetch('http://localhost:8080/login', {
                      method: 'POST',
                      datatype: 'json',
                      headers: {
                        'Content-Type': 'application/json',
                      },
                      body: JSON.stringify(mybody),
                    })
                      .then((res) => res.json())
                      .then((data) => console.log(data));
                  });
                </script>




                      """;
        return str;
    }

    @PostMapping("/login")
    public String doLogoin(@RequestBody UserDTO userDTO) {
        log.info("로그인을 시도했습니다 : " + userDTO);
        UsernamePasswordAuthenticationToken upaToken = new UsernamePasswordAuthenticationToken(userDTO.getUsername(),userDTO.getPassword());
        Authentication authentication = authenticationManager.authenticate(upaToken);
        if (authentication.isAuthenticated()) {
            String token = jwtProperties.generateToken(userDTO.getUsername());
            log.info("create token : " + token);
            return token;
        } else {
            throw new UsernameNotFoundException("Invalid user request!!!");
        }
    }

    @GetMapping(value = "/register")
    public String regist() {
        String str = "<h1>register</h1><br>";
        str += """
                  <form action='/register' method='post' id='form'>
                  <input type='text' name='username' />
                  <input type='password' name='password' />
                  <input type='email' name='email' />
                  <button type='submit'>gogo</button>
                </form>
                      """;
        return str;
    }

    @PostMapping(value = "/register")
    public String join(@RequestBody User user) {
        user.setUsername("id");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");

        log.info("save user : " + userService.saverUser(user));

        return "굿 회원가입";
    }

}