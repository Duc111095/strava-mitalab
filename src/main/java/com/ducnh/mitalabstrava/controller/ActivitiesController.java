package com.ducnh.mitalabstrava.controller;


import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.threeten.bp.OffsetDateTime;

import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.Configuration;
import io.swagger.client.api.ActivitiesApi;
import io.swagger.client.auth.*;
import io.swagger.client.model.DetailedAthlete;
import io.swagger.client.model.SummaryActivity;

@Controller
public class ActivitiesController {
	
	@GetMapping("/activities")
	public String getActivities(Model theModel) {
		// Get Code from authorization -> accessToken -> refreshToken
		
		ApiClient defaultClient = Configuration.getDefaultApiClient();
		
		OAuth strava_oauth = (OAuth) defaultClient.getAuthentication("strava_oauth");
		strava_oauth.setAccessToken("c416a2f615c0afb270fda2a04d0a6f0638195038");
		ActivitiesApi apiInstance = new ActivitiesApi();
		Integer before = 56;
		Integer after = 56;
		Integer page = 1;
		Integer perPage = 30;
		
		try {
			List<SummaryActivity> result = apiInstance.getLoggedInAthleteActivities(before, after, page, perPage);
			theModel.addAttribute("result", result);

		} catch (ApiException e) {
			System.err.println("Exception when calling ActivitiesApi");
			e.printStackTrace();
			theModel.addAttribute("result", e.getMessage());
		}
		
		return "activity";
	}
	
}
