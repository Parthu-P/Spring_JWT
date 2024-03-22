package com.parthu.jwt.service;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.parthu.jwt.entity.AutheticationResponse;
import com.parthu.jwt.entity.Token;
import com.parthu.jwt.entity.User;
import com.parthu.jwt.repository.TokenRepository;
import com.parthu.jwt.repository.UserRepository;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final TokenRepository tokenRepository;

	public AutheticationResponse register(User request) {

		if (repository.findByEmail(request.getEmail()).isPresent()) {
			return new AutheticationResponse(null, "User already exist", null);
		}
		User user = new User();

		user.setFirstname(request.getFirstname());
		user.setLastname(request.getLastname());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		user.setRole(request.getRole());

		user = repository.save(user);

		var jwt = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);

		saveUserToken(user, jwt);
		return new AutheticationResponse(jwt, "User registration was successful", refreshToken);
	}

	private void saveUserToken(User user, String jwt) {
		Token token = new Token();

		token.setToken(jwt);
		token.setLoggedOut(false);
		token.setUser(user);
		tokenRepository.save(token);
	}

	public AutheticationResponse authenticate(User request) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		User user = repository.findByEmail(request.getUsername()).orElseThrow();
		var token = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);

		revokeAllTokenByUser(user);
		saveUserToken(user, token);
		return new AutheticationResponse(token, "User login was successful", refreshToken);
	}

	private void revokeAllTokenByUser(User user) {
		List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
		if (validTokens.isEmpty()) {
			return;
		}
		validTokens.forEach(token -> {
			token.setLoggedOut(true);
		});
		tokenRepository.saveAll(validTokens);
	}

	public void refreshToken(HttpServletRequest request, HttpServletResponse response)
			throws IOException, StreamWriteException, DatabindException, java.io.IOException{

		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		final String refreshToken;
		final String email;
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return;
		}
		refreshToken = authHeader.substring(7);
		email = jwtService.extractUsername(refreshToken);

		if (email != null) {
			var user = this.repository.findByEmail(email).orElseThrow();
			if (jwtService.isValid(refreshToken, user)) {
				var accessToken = jwtService.generateToken(user);
				revokeAllTokenByUser(user);
				saveUserToken(user, accessToken);
				var authResponse = AutheticationResponse
						.builder().token(accessToken)
						.refreshToken(refreshToken)
						.build();
				new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
			}

		}
	}
}
