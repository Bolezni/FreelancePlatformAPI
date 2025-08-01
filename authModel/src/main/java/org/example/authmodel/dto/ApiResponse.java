package org.example.authmodel.dto;

import lombok.Getter;

@Getter
public class ApiResponse<T> {
    private final boolean  status;
    private final T data;
    private final String message;

    public ApiResponse(boolean status, T data, String message) {
        this.status = status;
        this.data = data;
        this.message = message;
    }
}
