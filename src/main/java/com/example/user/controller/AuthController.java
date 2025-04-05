package com.example.user.controller;

import com.example.user.dto.RegisterRequest;
import com.example.user.dto.UserDTO;
import com.example.user.service.AuthService;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import com.example.user.entity.User;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*") // КОРС для фронта
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;

    public AuthController(AuthenticationManager authenticationManager, AuthService authService) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
    }

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        authService.register(request);
        return "User registered successfully!";
    }

    @PostMapping("/login")
    public String login(@RequestBody RegisterRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            return "Login successful!";
        } catch (AuthenticationException e) {
            return "Login failed: " + e.getMessage();
        }
    }

    // Поиск пользователя по имени или email
    @GetMapping("/user/{usernameOrEmail}")
    public UserDTO getUserByUsernameOrEmail(@PathVariable String usernameOrEmail) {
        Optional<UserDTO> userDTO = authService.getUserByUsernameOrEmail(usernameOrEmail);
        if (userDTO.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        return userDTO.get();
    }
}
