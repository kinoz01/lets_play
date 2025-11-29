package com.example.lets_play.config;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.lets_play.dto.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Extends OncePerRequestFilter to ensure a single execution per request
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

	private static final int CAPACITY = 100;
	private static final long REFILL_WINDOW_MS = 60_000;

	private final Map<String, SimpleBucket> cache = new ConcurrentHashMap<>();
	@Autowired
    private ObjectMapper objectMapper;

	// Extends OncePerRequestFilter's doFilterInternal method that will be called in OncePerRequestFilter's doFilter() method
	// Tomcat → doFilter(...) (from OncePerRequestFilter) → our doFilterInternal(...)
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain nextFilter)
			throws ServletException, IOException {
		String ip = request.getRemoteAddr();
		SimpleBucket bucket = cache.computeIfAbsent(ip, this::createBucket);
		if (bucket.tryConsume(1)) {
			nextFilter.doFilter(request, response); // Calls the next filter in the chain or the target resource
		} else {
			response.setHeader("X-RateLimit-Limit", String.valueOf(CAPACITY));
			response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
			response.setContentType("application/json");
			ApiError error = new ApiError(HttpStatus.TOO_MANY_REQUESTS.value(), "Too Many Requests",
					"Rate limit exceeded. Please try again shortly.", request.getRequestURI());
			response.getWriter().write(objectMapper.writeValueAsString(error));
		}
	}

	private SimpleBucket createBucket(String key) {
		return new SimpleBucket(CAPACITY, REFILL_WINDOW_MS);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return "OPTIONS".equalsIgnoreCase(request.getMethod());
	}

	private static final class SimpleBucket {
		private final int capacity;
		private final long refillWindowMs;
		private double tokens;
		private long lastRefill;

		private SimpleBucket(int capacity, long refillWindowMs) {
			this.capacity = capacity;
			this.refillWindowMs = refillWindowMs;
			this.tokens = capacity;
			this.lastRefill = System.currentTimeMillis();
		}

		private synchronized boolean tryConsume(int amount) {
			refill();
			if (tokens >= amount) {
				tokens -= amount;
				return true;
			}
			return false;
		}

		private void refill() {
			long now = System.currentTimeMillis();
			long elapsed = now - lastRefill;
			if (elapsed <= 0) {
				return;
			}
			double tokensToAdd = (elapsed / (double) refillWindowMs) * capacity;
			if (tokensToAdd > 0) {
				tokens = Math.min(capacity, tokens + tokensToAdd);
				lastRefill = now;
			}
		}
	}
}
