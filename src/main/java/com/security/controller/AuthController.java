package com.security.controller;

import com.security.config.JwtUtil;
import com.security.config.LoginRequest;
import com.security.config.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        try {
            // 1. Authenticate
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // 2. Generate token
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtil.generateToken(userDetails);

            // 3. Get roles
            var roles = userDetails.getAuthorities()
                    .stream()
                    .map(auth -> auth.getAuthority())
                    .toList();

            // 4. Return response
            return ResponseEntity.ok(new LoginResponse(
                    userDetails.getUsername(),
                    token,
                    roles
            ));

        } catch (AuthenticationException e) {
            // Error response
            Map<String, Object> error = new HashMap<>();
            error.put("message", "Bad Credentials");
            error.put("status", false);

            return ResponseEntity.status(401).body(error);
        }
    }
}