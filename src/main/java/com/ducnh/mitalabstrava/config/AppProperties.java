package com.ducnh.mitalabstrava.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix="app")
public class AppProperties {
	private final Auth auth = new Auth();
	private final OAuth2 oauth2 = new OAuth2();
	
	public static class Auth {
		private String tokenSecret;
		private long tokenExpirationMsec;
		
		public String getTokenSecret() {
			return this.tokenSecret;
		}
		
		public void setTokenSecret(String tokenSecret) {
			this.tokenSecret = tokenSecret;
		}
		
		public long getTokenExpirationMsec() {
			return this.tokenExpirationMsec;
		}
		
		public void setTokenExpirationMsec(long tokenExpirationMsec) {
			this.tokenExpirationMsec = tokenExpirationMsec;
		}
	}
	
	public static final class OAuth2 {
		private List<String> authorizedRedirectUris = new ArrayList<>();
		
		public List<String> getAuthorizedRedirectUris() {
			return this.authorizedRedirectUris;
		}
		
		public OAuth2 authorizedRedirectUri(List<String> authorizedRedirectUris) {
			this.authorizedRedirectUris = authorizedRedirectUris;
			return this;
		}
	}
	
	public Auth getAuth() {
		return auth;
	}
	
	public OAuth2 getOauth2() {
		return oauth2;
	}
}
