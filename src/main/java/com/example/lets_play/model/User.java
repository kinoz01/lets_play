package com.example.lets_play.model;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Document(collection = "users")
@Getter
@Setter
public class User implements UserDetails {

	@Id
	private String id;

	@Field("name")
	@NotBlank
	@Size(min = 2, max = 50)
	private String name;

	@Field("email")
	@NotBlank
	@Email
	private String email;

	@Field("password")
	@NotBlank
	@Size(min = 8, message = "Password should at least be 8 characters")
	private String password;

	@Field("role")
	private Role role = Role.USER;

	@Field("created_at")
	private Instant createdAt = Instant.now();

	@Field("updated_at")
	private Instant updatedAt = Instant.now();

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
