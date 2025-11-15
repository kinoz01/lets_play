package com.example.lets_play.dto;

import java.time.Instant;

import lombok.Data;

@Data
public class ProductResponse {

	private String id;
	private String name;
	private String description;
	private Double price;
	private String userId;
	private Instant createdAt;
	private Instant updatedAt;
}
