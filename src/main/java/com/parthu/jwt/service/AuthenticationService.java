package com.parthu.jwt.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.parthu.jwt.entity.AutheticationResponse;
import com.parthu.jwt.entity.User;
import com.parthu.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AutheticationResponse register(User request) {

		if (repository.findByEmail(request.getEmail()).isPresent()) {
			return new AutheticationResponse(null, "User already exist");
		}
		User user = new User();

		user.setFirstname(request.getFirstname());
		user.setLastname(request.getLastname());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		user.setRole(request.getRole());

		user = repository.save(user);

		String token = jwtService.generateToken(user);
		return new AutheticationResponse(token, "User registration was successful");
	}

	public AutheticationResponse authenticate(User request) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		User user = repository.findByEmail(request.getUsername()).orElseThrow();
		String token = jwtService.generateToken(user);
		return new AutheticationResponse(token,  "User login was successful");
	}
}
