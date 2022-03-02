package com.awscognito.service;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.awscognito.controller.UserDetail;

@RestController
@RequestMapping("/user")
public class UserDetailImpl {
	 @ResponseBody 
	 @GetMapping("/detail")
	    public UserDetail getUserDetail() {

		 UserDetail userDetail = new UserDetail();
	        userDetail.setfirstName("Gaurav");
	        userDetail.setlastName("Saini");
	        userDetail.setEmail("gauravdope.1998@gmail.com");
	        return userDetail;
	    }
}
