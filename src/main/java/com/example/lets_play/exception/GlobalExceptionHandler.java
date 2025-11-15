package com.example.lets_play.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

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

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR,
				"An unexpected error occurred. Please contact support if the issue persists.", request);
	}

	private ResponseEntity<ApiError> buildResponse(HttpStatus status, String message, WebRequest request) {
		ApiError error = new ApiError(status.value(), status.getReasonPhrase(), message,
				request.getDescription(false).replace("uri=", ""));
		return new ResponseEntity<>(error, status);
	}
}
