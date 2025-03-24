package com.ducnh.mitalabstrava.security.oauth2;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.ducnh.mitalabstrava.exception.OAuth2AuthenticationProcessingException;
import com.ducnh.mitalabstrava.model.AuthProvider;
import com.ducnh.mitalabstrava.model.User;
import com.ducnh.mitalabstrava.repository.UserRepository;
import com.ducnh.mitalabstrava.security.UserPrincipal;
import com.ducnh.mitalabstrava.security.oauth2.user.OAuth2UserInfo;
import com.ducnh.mitalabstrava.security.oauth2.user.OAuth2UserInfoFactory;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService{
	public static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

	@Autowired
	private UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
		
		logger.info("On CustomOAuth2UserService loadUser...");

		try {
			return processOAuth2User(oAuth2UserRequest, oAuth2User);
		} catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
		}
	}
	
	private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
		oAuth2User.getAttributes().forEach((attribute, object) -> logger.info(attribute + ": "+ String.valueOf(object)));
		OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
		
		if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
			throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
		}
		
		logger.info("On CustomOAuth2UserService processUser...");
		
		Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
		User user;
		if (userOptional.isPresent()) {
			user = userOptional.get();
			if (!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
				throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " + 
						user.getProvider() + " account. Please use your " + user.getProvider() + 
						" account to login.");
			}
			user = updateExistingUser(user, oAuth2UserInfo);
			logger.info("On CustomOAuth2UserService updating Existing User...");

		} else {
			user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
			logger.info("On CustomOAuth2UserService registering existing User...");
		}
		return UserPrincipal.create(user, oAuth2User.getAttributes());
	}
	
	private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
		User user = new User();
		
		user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
		user.setProviderId(oAuth2UserInfo.getId());
		user.setName(oAuth2UserInfo.getName());
		user.setEmail(oAuth2UserInfo.getEmail());
		user.setImageUrl(oAuth2UserInfo.getImageUrl());
		return userRepository.save(user);
	}
	
	private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
		existingUser.setName(oAuth2UserInfo.getName());
		existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
		return userRepository.save(existingUser);
	}
}
