package com.example.user.controller;

import com.example.user.dto.LoginRequest;
import com.example.user.dto.UserDTO;
import com.example.user.service.AuthService;
import com.example.user.security.JwtService;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthController(AuthService authService,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtService.generateToken(request.getUsername());

        ResponseCookie cookie = ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(true) // true для HTTPS, можно временно false для localhost
                .path("/")
                .maxAge(24 * 60 * 60) // 1 день
                .sameSite("Lax")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Login success");
    }


    @GetMapping("/user/{usernameOrEmail}")
    public UserDTO getUserByUsernameOrEmail(@PathVariable String usernameOrEmail) {
        Optional<UserDTO> userDTO = authService.getUserByUsernameOrEmail(usernameOrEmail);
        if (userDTO.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        return userDTO.get();
    }

    @GetMapping("/users/profile")
    public ResponseEntity<UserDTO> getCurrentUserProfile(Authentication authentication) {
        // Получаем имя пользователя из контекста безопасности
        String usernameOrEmail = authentication.getName(); // Имя пользователя или email из контекста

        // Ищем пользователя по имени или email с помощью authService
        Optional<UserDTO> userDTO = authService.getUserByUsernameOrEmail(usernameOrEmail);

        return userDTO.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(null));

    }

}
