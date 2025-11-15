package com.example.lets_play.service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.lets_play.dto.ProductRequest;
import com.example.lets_play.dto.ProductResponse;
import com.example.lets_play.dto.ProductUpdateRequest;
import com.example.lets_play.exception.ForbiddenException;
import com.example.lets_play.exception.ResourceNotFoundException;
import com.example.lets_play.exception.UnauthorizedException;
import com.example.lets_play.model.Product;
import com.example.lets_play.model.Role;
import com.example.lets_play.model.User;
import com.example.lets_play.repository.ProductRepository;

@Service
public class ProductService {

	private final ProductRepository productRepository;

	@Autowired
	public ProductService(ProductRepository productRepository) {
		this.productRepository = productRepository;
	}

	public List<ProductResponse> getAllProducts() {
		return productRepository.findAll().stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	public ProductResponse getProductById(String id) {
		Product product = productRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Product not found with id: " + id));
		return mapToResponse(product);
	}

	public List<ProductResponse> getProductsForUser(String userId) {
		return productRepository.findAllByUserId(userId).stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	public ProductResponse createProduct(ProductRequest request, User owner) {
		if (owner == null) {
			throw new UnauthorizedException("Authentication required");
		}
		Instant now = Instant.now();
		Product product = new Product();
		product.setName(request.getName());
		product.setDescription(request.getDescription());
		product.setPrice(request.getPrice());
		product.setUserId(owner.getId());
		product.setCreatedAt(now);
		product.setUpdatedAt(now);
		Product saved = productRepository.save(product);
		return mapToResponse(saved);
	}

	public ProductResponse updateProduct(String id, ProductUpdateRequest request, User requester) {
		if (requester == null) {
			throw new UnauthorizedException("Authentication required");
		}
		Product product = productRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Product not found with id: " + id));
		boolean isOwner = product.getUserId().equals(requester.getId());
		boolean isAdmin = requester.getRole() == Role.ADMIN;
		if (!isOwner && !isAdmin) {
			throw new ForbiddenException("You are not allowed to update this product");
		}
		if (request.getName() != null) {
			product.setName(request.getName());
		}
		if (request.getDescription() != null) {
			product.setDescription(request.getDescription());
		}
		if (request.getPrice() != null) {
			product.setPrice(request.getPrice());
		}
		product.setUpdatedAt(Instant.now());
		Product updated = productRepository.save(product);
		return mapToResponse(updated);
	}

	public void deleteProduct(String id, User requester) {
		if (requester == null) {
			throw new UnauthorizedException("Authentication required");
		}
		Product product = productRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Product not found with id: " + id));
		boolean isOwner = product.getUserId().equals(requester.getId());
		boolean isAdmin = requester.getRole() == Role.ADMIN;
		if (!isOwner && !isAdmin) {
			throw new ForbiddenException("You are not allowed to delete this product");
		}
		productRepository.delete(product);
	}

	private ProductResponse mapToResponse(Product product) {
		ProductResponse response = new ProductResponse();
		response.setId(product.getId());
		response.setName(product.getName());
		response.setDescription(product.getDescription());
		response.setPrice(product.getPrice());
		response.setUserId(product.getUserId());
		response.setCreatedAt(product.getCreatedAt());
		response.setUpdatedAt(product.getUpdatedAt());
		return response;
	}
}
