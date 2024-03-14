package com.parthu.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.parthu.jwt.entity.AutheticationResponse;
import com.parthu.jwt.entity.User;
import com.parthu.jwt.service.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {
	
	private final AuthenticationService authenticationService;
	
	@PostMapping("/register")
	public ResponseEntity<AutheticationResponse> register(@RequestBody User request){
		return ResponseEntity.ok(authenticationService.register(request));
	}
	
	@GetMapping("/login")
	public ResponseEntity<AutheticationResponse> login(@RequestBody User request){
		return ResponseEntity.ok(authenticationService.authenticate(request));
	}
}
