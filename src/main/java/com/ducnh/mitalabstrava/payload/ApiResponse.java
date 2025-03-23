package com.ducnh.mitalabstrava.payload;

public class ApiResponse {

	private boolean success;
	private String message;
	
	public ApiResponse(boolean success, String message) {
		this.success = success;
		this.message = message;
	}
	
	public boolean isSuccess() {
		return this.success;
	}

	public String getMessage() {
		return this.message;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}
	
	public void setMessage(String message) {
		this.message = message;
	}
}

