package com.ducnh.mitalabstrava.security.oauth2.user;

import java.util.Map;

import com.ducnh.mitalabstrava.exception.OAuth2AuthenticationProcessingException;
import com.ducnh.mitalabstrava.model.AuthProvider;

public class OAuth2UserInfoFactory {

	public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
		if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
			return new GithubOAuth2UserInfo(attributes);
		} else if (registrationId.equalsIgnoreCase(AuthProvider.strava.toString())) {
			return new StravaOAuth2UserInfo(attributes);
		}
		
		throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported.");
	}
}
