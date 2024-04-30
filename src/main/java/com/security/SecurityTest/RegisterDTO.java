package com.security.SecurityTest;

import org.springframework.beans.factory.annotation.Autowired;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data // risky
public class RegisterDTO {
    
    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    private String username;

    @NotEmpty
    private String email;

    private String phone;

    private String address;

    @NotEmpty
    @Size(min = 6, message = "Min password length is 6")
    private String password;
    
}   
