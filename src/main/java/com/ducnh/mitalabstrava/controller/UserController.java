package com.ducnh.mitalabstrava.controller;

import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ducnh.mitalabstrava.exception.ResourceNotFoundException;
import com.ducnh.mitalabstrava.model.User;
import com.ducnh.mitalabstrava.repository.UserRepository;
import com.ducnh.mitalabstrava.security.CurrentUser;
import com.ducnh.mitalabstrava.security.UserPrincipal;

@RestController
public class UserController {
	
	@Autowired
	private UserRepository userRepo;
	
	@GetMapping("/user/me")
	@PreAuthorize("hasRole('USER')")
	public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
		return userRepo.findById(userPrincipal.getId())
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
	}
	
	@GetMapping("/user")
    public Map<String, Object> user(@CurrentUser OAuth2User principal) {
        return Collections.singletonMap("name", principal.getAttribute("name"));
    }
}
