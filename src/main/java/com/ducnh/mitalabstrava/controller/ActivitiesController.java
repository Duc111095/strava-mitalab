package com.ducnh.mitalabstrava.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.threeten.bp.OffsetDateTime;

import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.Configuration;
import io.swagger.client.api.ActivitiesApi;
import io.swagger.client.auth.*;
import io.swagger.client.model.DetailedActivity;

@Controller
public class ActivitiesController {
	@GetMapping("/activities")
	public String getActivities() {
		ApiClient defaultClient = Configuration.getDefaultApiClient();
		
		OAuth strava_oauth = (OAuth) defaultClient.getAuthentication("strava_oauth");
		strava_oauth.setAccessToken("TOKEN");
		ActivitiesApi apiInstance = new ActivitiesApi();
		String name = "Duc's activity";
		String sportType = "sportType_example";
		OffsetDateTime startDateLocal = OffsetDateTime.now();
		String type = "Run";
		String description = "description_example";
		Float distance = 3.4F;
		Integer trainer = 56;
		Integer commute = 56;
		
		try {
			DetailedActivity result = apiInstance.createActivity(name, sportType, startDateLocal, commute, type
					, description, distance, trainer, commute);
			System.out.println(result);
		} catch (ApiException e) {
			System.err.println("Exception when calling ActivitiesApi");
			e.printStackTrace();
			
		}
		
		return "activity.jsp";
	}
	
}
