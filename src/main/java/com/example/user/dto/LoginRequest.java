// LoginRequest.java
package com.example.user.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class LoginRequest {
    private String username;
    private String password;
    @Setter
    @Getter
    private boolean remember;

}
