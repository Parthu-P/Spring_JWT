package com.parthu.jwt.service;

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.parthu.jwt.entity.AutheticationResponse;
import com.parthu.jwt.entity.Token;
import com.parthu.jwt.entity.User;
import com.parthu.jwt.repository.TokenRepository;
import com.parthu.jwt.repository.UserRepository;

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
			return new AutheticationResponse(null, "User already exist");
		}
		User user = new User();

		user.setFirstname(request.getFirstname());
		user.setLastname(request.getLastname());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		user.setRole(request.getRole());

		user = repository.save(user);

		String jwt = jwtService.generateToken(user);

		saveUserToken(user, jwt);
		return new AutheticationResponse(jwt, "User registration was successful");
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
		String token = jwtService.generateToken(user);

		revokeAllTokenByUser(user);
		saveUserToken(user, token);
		return new AutheticationResponse(token, "User login was successful");
	}

	private void revokeAllTokenByUser(User user) {
		List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
		if (validTokens.isEmpty()) {
			return;
		}

		validTokens.forEach(t -> {
			t.setLoggedOut(true);
		});
	}
}
