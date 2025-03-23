package com.ducnh.mitalabstrava.payload;

public class AuthResponse {

	private String accessToken;
	private String tokenType = "Bearer";
	
	public AuthResponse(String accessToken) {
		this.accessToken = accessToken;
	}
	
	public String getAccessToken() {
		return this.accessToken;
	}
	
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	public String getTokenType() {
		return this.tokenType;
	}
	
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
}
