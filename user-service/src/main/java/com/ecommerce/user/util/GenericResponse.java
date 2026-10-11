package com.ecommerce.user.util;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GenericResponse<T> {

    // Indicates whether the business operation succeeded or failed
    private Boolean success;

    // Human-readable message (e.g. "User registered successfully", "Invalid password")
    private String message;

    // Generic generic data payload (User object, Token map, etc.)
    private T data;

    /**
     * Helper to create a successful response with default "success" message.
     */
    public static <T> GenericResponse<T> success(T data) {
        return GenericResponse.<T>builder()
                .success(true)
                .message("success")
                .data(data)
                .build();
    }

    /**
     * Helper to create a successful response with a customized business message.
     */
    public static <T> GenericResponse<T> success(T data, String message) {
        return GenericResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .build();
    }

    /**
     * Helper to create an error response with default "error" message.
     */
    public static <T> GenericResponse<T> error(T data) {
        return GenericResponse.<T>builder()
                .success(false)
                .message("error")
                .data(data)
                .build();
    }

    /**
     * Helper to create an error response with a descriptive error message.
     */
    public static <T> GenericResponse<T> error(T data, String message) {
        return GenericResponse.<T>builder()
                .success(false)
                .message(message)
                .data(data)
                .build();
    }
}

