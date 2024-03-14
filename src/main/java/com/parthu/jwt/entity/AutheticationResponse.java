package com.parthu.jwt.entity;

public class AutheticationResponse {

	 private String token;
	    private String message;

	    public AutheticationResponse(String token, String message) {
	        this.token = token;
	        this.message = message;
	    }

	    public String getToken() {
	        return token;
	    }

	    public String getMessage() {
	        return message;
	    }
}
