package com.parthu.jwt.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.parthu.jwt.entity.User;
import com.parthu.jwt.repository.TokenRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtService {
	
	private final TokenRepository tokenRepository;
	
	@Value("${application.security.jwt.secret-key}")
	private String secretkey;
	
	@Value("${application.security.jwt.expiration}")
	private Long jwtExpiratin;
	
	@Value("${application.security.jwt.refresh-token.expiration}")
	private Long refreshExpiratin;

	public String extractUsername(String token) {
		return extractClaims(token, Claims::getSubject);
	}
	
	public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);

        boolean validToken = tokenRepository
                .findByToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);

        return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;
    }
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaims(token, Claims::getExpiration);
	}

	public<T> T extractClaims(String token, Function<Claims, T> resolver) {
		Claims claims=extractAllClaims(token);
		return resolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
				.verifyWith(getSigninKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
	
	public String generateToken(User user) {
		return buildToken(user, jwtExpiratin);
	}
	
	public String generateRefreshToken(User user) {
		return buildToken(user, refreshExpiratin);
	}
	
	private String buildToken(User user, Long expiration) {
		
		String token=Jwts
				.builder()
				.subject(user.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+expiration))
				.signWith(getSigninKey())
				.compact();
		return token;
		
	}
	
	public SecretKey getSigninKey() {
		byte[] keyBytes=Decoders.BASE64URL.decode(secretkey);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
