package org.example.authmodel.dto;

import jakarta.validation.constraints.NotBlank;

public record RegisterRequest (
        @NotBlank
        String firstname,
        @NotBlank
        String lastname,
        @NotBlank
        String email,
        @NotBlank
        String username,
        @NotBlank
        String password
){
}
