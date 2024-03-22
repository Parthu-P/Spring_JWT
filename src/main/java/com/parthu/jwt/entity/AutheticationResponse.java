package com.parthu.jwt.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AutheticationResponse {

	private String token;
	private String message;
	
	@JsonProperty("refresh_token")
	private String refreshToken;

}
