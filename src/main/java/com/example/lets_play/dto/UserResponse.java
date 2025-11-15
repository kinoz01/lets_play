package com.example.lets_play.dto;

import java.time.Instant;

import com.example.lets_play.model.Role;

import lombok.Data;

@Data
public class UserResponse {
	private String id;
	private String name;
	private String email;
	private Role role;
	private Instant createdAt;
	private Instant updatedAt;
}
