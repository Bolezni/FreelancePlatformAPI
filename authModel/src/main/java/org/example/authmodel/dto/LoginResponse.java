package org.example.authmodel.dto;

public record LoginResponse(
        String id,
        String username,
        String email,
        String sessionId,
        String csrfToken
) {
}
