package com.ducnh.mitalabstrava.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.ducnh.mitalabstrava.exception.BadRequestException;
import com.ducnh.mitalabstrava.model.AuthProvider;
import com.ducnh.mitalabstrava.model.User;
import com.ducnh.mitalabstrava.payload.ApiResponse;
import com.ducnh.mitalabstrava.payload.AuthResponse;
import com.ducnh.mitalabstrava.payload.LoginRequest;
import com.ducnh.mitalabstrava.payload.SignUpRequest;
import com.ducnh.mitalabstrava.repository.UserRepository;
import com.ducnh.mitalabstrava.security.TokenProvider;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private TokenProvider tokenProvider;

	@PostMapping("/login")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getEmail(),
						loginRequest.getPassword()));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String token = tokenProvider.createToken(authentication);
		return ResponseEntity.ok(new AuthResponse(token));
	}
	
	@GetMapping("/")
	public ResponseEntity<?> login() {
		return ResponseEntity.ok("Hello everyone!");
	}
	
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signupRequest) {
		if (userRepository.existsByEmail(signupRequest.getEmail())) {
			throw new BadRequestException("Email address already in use.");
		}
		
		// Create user's account
		
		User user = new User();
		user.setName(signupRequest.getName());
		user.setEmail(signupRequest.getEmail());
		user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
		user.setProvider(AuthProvider.local);
		
		User result = userRepository.save(user);
		
		URI location = ServletUriComponentsBuilder
				.fromCurrentContextPath().path("/user/me")
				.buildAndExpand(result.getId()).toUri();
		
		return ResponseEntity.created(location)
				.body(new ApiResponse(true, "User registered successfully@"));
	}
}
