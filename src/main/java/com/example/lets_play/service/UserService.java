package com.example.lets_play.service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.lets_play.dto.UserRequest;
import com.example.lets_play.dto.UserResponse;
import com.example.lets_play.dto.UserUpdateRequest;
import com.example.lets_play.exception.BadRequestException;
import com.example.lets_play.exception.ForbiddenException;
import com.example.lets_play.exception.ResourceNotFoundException;
import com.example.lets_play.exception.UnauthorizedException;
import com.example.lets_play.model.Role;
import com.example.lets_play.model.User;
import com.example.lets_play.repository.UserRepository;

@Service
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Autowired
	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	public List<UserResponse> getAllUsers() {
		return userRepository.findAll().stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	public UserResponse getUserById(String id) {
		User user = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
		return mapToResponse(user);
	}

	public UserResponse createUser(UserRequest request) {
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new BadRequestException("Email already exists");
		}
		User user = new User();
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(request.getRole() == null ? Role.USER : request.getRole());
		user.setCreatedAt(Instant.now());
		user.setUpdatedAt(Instant.now());
		User saved = userRepository.save(user);
		return mapToResponse(saved);
	}

	public UserResponse updateUser(String id, UserUpdateRequest request, User requester) {
		if (requester == null) {
			throw new UnauthorizedException("Authentication required");
		}
		User user = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
		boolean isAdmin = requester.getRole() == Role.ADMIN;
		boolean isOwner = user.getId().equals(requester.getId());

		if (!isAdmin && !isOwner) {
			throw new ForbiddenException("You are not allowed to update this user");
		}

		if (request.getName() != null) {
			user.setName(request.getName());
		}
		if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
			if (userRepository.existsByEmail(request.getEmail())) {
				throw new BadRequestException("Email already exists");
			}
			user.setEmail(request.getEmail());
		}
		if (request.getPassword() != null) {
			user.setPassword(passwordEncoder.encode(request.getPassword()));
		}
		if (request.getRole() != null) {
			if (!isAdmin) {
				throw new ForbiddenException("Only administrators can change roles");
			}
			user.setRole(request.getRole());
		}
		user.setUpdatedAt(Instant.now());
		User updated = userRepository.save(user);
		return mapToResponse(updated);
	}

	public void deleteUser(String id) {
		if (!userRepository.existsById(id)) {
			throw new ResourceNotFoundException("User not found with id: " + id);
		}
		userRepository.deleteById(id);
	}

	private UserResponse mapToResponse(User user) {
		UserResponse response = new UserResponse();
		response.setId(user.getId());
		response.setName(user.getName());
		response.setEmail(user.getEmail());
		response.setRole(user.getRole());
		response.setCreatedAt(user.getCreatedAt());
		response.setUpdatedAt(user.getUpdatedAt());
		return response;
	}
}
