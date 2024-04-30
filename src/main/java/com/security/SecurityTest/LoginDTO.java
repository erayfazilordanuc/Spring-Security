package com.security.SecurityTest;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data // risky
public class LoginDTO {
    
    @NotEmpty
    private String username;

    @NotEmpty
    private String password;

}
