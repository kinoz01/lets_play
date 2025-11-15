package com.example.lets_play.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthResponse {
	private String token;
	private String tokenType = "Bearer";
	private long expiresIn;

	public AuthResponse(String token, long expiresIn) {
		this.token = token;
		this.expiresIn = expiresIn;
	}
}
