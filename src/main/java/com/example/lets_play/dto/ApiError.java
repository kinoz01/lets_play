package com.example.lets_play.dto;

import java.time.Instant;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class ApiError {
	private Instant timestamp = Instant.now();
	private int status;
	private String error;
	private String message;
	private String path;

	public ApiError(int status, String error, String message, String path) {
		this.status = status;
		this.error = error;
		this.message = message;
		this.path = path;
	}
}
