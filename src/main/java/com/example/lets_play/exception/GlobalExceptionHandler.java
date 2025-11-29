package com.example.lets_play.exception;

import java.util.stream.Collectors;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import com.example.lets_play.dto.ApiError;

import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<ApiError> handleNotFound(ResourceNotFoundException ex, WebRequest request) {
		return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage(), request);
	}

	@ExceptionHandler({ BadRequestException.class, ConstraintViolationException.class })
	public ResponseEntity<ApiError> handleBadRequest(Exception ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
	}

	@ExceptionHandler(UnauthorizedException.class)
	public ResponseEntity<ApiError> handleUnauthorized(UnauthorizedException ex, WebRequest request) {
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
	}

	@ExceptionHandler(ForbiddenException.class)
	public ResponseEntity<ApiError> handleForbidden(ForbiddenException ex, WebRequest request) {
		return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage(), request);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
		StringBuilder builder = new StringBuilder();
		for (FieldError error : ex.getBindingResult().getFieldErrors()) {
			builder.append(error.getField()).append(" ").append(error.getDefaultMessage()).append("; ");
		}
		return buildResponse(HttpStatus.BAD_REQUEST, builder.toString().trim(), request);
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<ApiError> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex,
			WebRequest request) {
		String supported = ex.getSupportedHttpMethods() == null ? "none"
				: ex.getSupportedHttpMethods().stream().map(HttpMethod::name).collect(Collectors.joining(", "));
		String message = String.format("Request method '%s' is not supported. Supported methods: %s", ex.getMethod(),
				supported);
		return buildResponse(HttpStatus.METHOD_NOT_ALLOWED, message, request);
	}

	@ExceptionHandler(NoHandlerFoundException.class)
	public ResponseEntity<ApiError> handleNoHandler(NoHandlerFoundException ex, WebRequest request) {
		String message = String.format("No handler found for %s %s", ex.getHttpMethod(), ex.getRequestURL());
		return buildResponse(HttpStatus.NOT_FOUND, message, request);
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Request body is missing or malformed", request);
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
		String message = ex.getMessage() == null ? "Access denied" : ex.getMessage();
		return buildResponse(HttpStatus.FORBIDDEN, message, request);
	}

	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<ApiError> handleAuthentication(AuthenticationException ex, WebRequest request) {
		return buildResponse(HttpStatus.UNAUTHORIZED, "Authentication required", request);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Unsupported request.", request);
	}

	private ResponseEntity<ApiError> buildResponse(HttpStatus status, String message, WebRequest request) {
		ApiError error = new ApiError(status.value(), status.getReasonPhrase(), message,
				request.getDescription(false).replace("uri=", ""));
		return new ResponseEntity<>(error, status);
	}
}
