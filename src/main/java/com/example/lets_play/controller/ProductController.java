package com.example.lets_play.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.lets_play.dto.ProductRequest;
import com.example.lets_play.dto.ProductResponse;
import com.example.lets_play.dto.ProductUpdateRequest;
import com.example.lets_play.model.User;
import com.example.lets_play.service.ProductService;

import jakarta.annotation.security.PermitAll;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/products")
public class ProductController {

	private final ProductService productService;

	public ProductController(ProductService productService) {
		this.productService = productService;
	}

	@GetMapping
	@PermitAll
	public ResponseEntity<List<ProductResponse>> getProducts() {
		return ResponseEntity.ok(productService.getAllProducts());
	}

	@GetMapping("/{id}")
	@PermitAll
	public ResponseEntity<ProductResponse> getProduct(@PathVariable String id) {
		return ResponseEntity.ok(productService.getProductById(id));
	}

	@GetMapping("/me")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<List<ProductResponse>> getMyProducts(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(productService.getProductsForUser(currentUser.getId()));
	}

	@PostMapping
	@PreAuthorize("hasAnyRole('ADMIN','USER')")
	public ResponseEntity<ProductResponse> createProduct(@Valid @RequestBody ProductRequest request,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(productService.createProduct(request, currentUser));
	}

	@PutMapping("/{id}")
	@PreAuthorize("hasAnyRole('ADMIN','USER')")
	public ResponseEntity<ProductResponse> updateProduct(@PathVariable String id,
			@Valid @RequestBody ProductUpdateRequest request, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(productService.updateProduct(id, request, currentUser));
	}

	@PatchMapping("/{id}")
	@PreAuthorize("hasAnyRole('ADMIN','USER')")
	public ResponseEntity<ProductResponse> partiallyUpdateProduct(@PathVariable String id,
			@RequestBody ProductUpdateRequest request, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(productService.updateProduct(id, request, currentUser));
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasAnyRole('ADMIN','USER')")
	public ResponseEntity<Void> deleteProduct(@PathVariable String id, @AuthenticationPrincipal User currentUser) {
		productService.deleteProduct(id, currentUser);
		return ResponseEntity.noContent().build();
	}
}
