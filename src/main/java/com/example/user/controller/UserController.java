package com.example.user.controller;

import com.example.user.dto.UserDTO;
import com.example.user.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/profile")
    public ResponseEntity<UserDTO> getCurrentUserProfile(Authentication authentication) {
        String usernameOrEmail = authentication.getName(); // Получаем имя пользователя из контекста безопасности

        Optional<UserDTO> userDTO = authService.getUserByUsernameOrEmail(usernameOrEmail);

        return userDTO.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(null));
    }

    @GetMapping("/{usernameOrEmail}")
    public UserDTO getUserByUsernameOrEmail(@PathVariable String usernameOrEmail) {
        Optional<UserDTO> userDTO = authService.getUserByUsernameOrEmail(usernameOrEmail);
        if (userDTO.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        return userDTO.get();
    }
}
