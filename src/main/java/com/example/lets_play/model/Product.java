package com.example.lets_play.model;

import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Document(collection = "products")
@Getter
@Setter
public class Product {

	@Id
	private String id;

	@Field("name")
	@NotBlank
	@Size(min = 2, max = 50)
	private String name;

	@Field("description")
	@NotBlank
	@Size(min = 5, max = 255)
	private String description;

	@Field("price")
	@NotNull
	@DecimalMin(value = "0.0", inclusive = false)
	private Double price;

	@Field("user_id")
	@NotBlank
	private String userId;

	@Field("created_at")
	private Instant createdAt = Instant.now();

	@Field("updated_at")
	private Instant updatedAt = Instant.now();

}
