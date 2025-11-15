package com.example.lets_play.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ProductUpdateRequest {

	@Size(min = 2, max = 50)
	private String name;

	@Size(min = 5, max = 255)
	private String description;

	@DecimalMin(value = "0.0", inclusive = false)
	private Double price;
}
