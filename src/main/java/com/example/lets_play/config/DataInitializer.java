package com.example.lets_play.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.lets_play.model.Role;
import com.example.lets_play.model.User;
import com.example.lets_play.repository.UserRepository;

@Component // Marks this class as a Spring-managed component, which means it will be detected during component scanning and instantiated as a bean
public class DataInitializer implements CommandLineRunner {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final String adminEmail;
	private final String adminPassword;

	// Instantiated during application startup, DIng the UserRepository and PasswordEncoder
	// UserRespostory is an instance of a proxy class that Spring Data MongoDB creates and inject at runtime
	public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder,
			@Value("${app.admin.email:admin@letsplay.dev}") String adminEmail,
			@Value("${app.admin.password:Admin123!}") String adminPassword) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.adminEmail = adminEmail;
		this.adminPassword = adminPassword;
	}

	// Called after the application context is loaded and right before the Spring Application run method is completed
	// Used to seed the database with initial data
	@Override
	public void run(String... args) {
		if (!userRepository.existsByEmail(adminEmail)) {
			User admin = new User();
			admin.setName("System Admin");
			admin.setEmail(adminEmail);
			admin.setPassword(passwordEncoder.encode(adminPassword));
			admin.setRole(Role.ADMIN);
			userRepository.save(admin);
		}
	}
}
