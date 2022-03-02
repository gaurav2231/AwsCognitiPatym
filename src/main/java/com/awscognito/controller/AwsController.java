package com.awscognito.controller;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.InvalidParameterException;
import com.awscognito.model.MessageResponse;
import com.awscognito.model.UserSignupRequest;
import com.awscognito.model.UsersigninRequest;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;

@RestController
@RequestMapping("/test")
public class AwsController {

 @Autowired
 AWSCognitoIdentityProvider  cognitoClient;

	@Value("${aws.cognito.clientId}")
	String clientId;
	@Value("${aws.cognito.clientSecret}")
	String clientSecret;
	@Value("${aws.access-key}")
	String accessKey;
	@Value("${aws.access-secret}")
	String secretKey;
	@Value("${aws.cognito.userPoolId}")
	String userPoolId;
	@Value("${aws.cognito.region}")
	private Region region;

	// Signup
	@PostMapping("/signup")
	public ResponseEntity<MessageResponse> signup(@RequestBody UserSignupRequest userSignUp) 
	 {
		MessageResponse msg=new MessageResponse();
		
		CognitoIdentityProviderClient client=CognitoIdentityProviderClient.builder().region(region.US_EAST_1).build();

		AttributeType attributeType = AttributeType.builder()
				             .name("email").value(userSignUp.getEmail())
				             .build();
		
		ArrayList<AttributeType> attriArray=new ArrayList<>();
		attriArray.add(attributeType);
		try {		
			String secretVal = calculateSecretHash(clientId, clientSecret, userSignUp.getEmail());
			
			SignUpRequest signUp=SignUpRequest.builder()
					.userAttributes(attriArray)
					.username(userSignUp.getEmail())
					//.username(userSignUp.getUsername())
					.clientId(clientId)
					.password(userSignUp.getPassword())
					.secretHash(secretVal).build();
		   client.signUp(signUp);
	   }
		  catch(CognitoIdentityProviderException e) {
			  String errormsg=e.awsErrorDetails().errorMessage();
			  msg.setMessage(errormsg);
			 return ResponseEntity.ok(msg);
		}
		msg.setMessage("User Registered Successfully");
	return ResponseEntity.ok(msg);
}
	                        // Signin
	@PostMapping("/signin")      
	public ResponseEntity<?> login(@RequestBody UsersigninRequest usersigninRequest) throws Exception{
		MessageResponse msg=new MessageResponse();

		UserSignInResponse userSignInResponse = new UserSignInResponse();

		final Map<String, String> authParams = new HashMap<>();
	//	authParams.put("USERNAME", usersigninRequest.getUsername());
		authParams.put("USERNAME", usersigninRequest.getEmail());
		authParams.put("PASSWORD", usersigninRequest.getPassword());
		authParams.put("SECRET_HASH", calculateSecretHash(clientId, clientSecret,usersigninRequest.getEmail()));
	
		final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();

		authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH).withClientId(clientId)
		.withUserPoolId(userPoolId).withAuthParameters(authParams);
try {
		AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);
        AuthenticationResultType authenticationResult = null;
     System.out.println(result);
     
//     final Map<String, String> challengeResponses = new HashMap<>();
//       challengeResponses.put("EMAIL", usersigninRequest.getEmail());
//     challengeResponses.put("PASSWORD", usersigninRequest.getPassword());
//     challengeResponses.put("SECRET_HASH", calculateSecretHash(clientId, clientSecret,usersigninRequest.getEmail()));
    

final AdminRespondToAuthChallengeRequest request = new AdminRespondToAuthChallengeRequest()
                     .withChallengeName(ChallengeNameType.ADMIN_NO_SRP_AUTH)
                     .withChallengeResponses(authParams)
                     .withClientId(clientId).withUserPoolId(userPoolId)
                     .withSession(result.getSession());

        AdminRespondToAuthChallengeResult resultChallenge =cognitoClient.adminRespondToAuthChallenge(request);
        authenticationResult = resultChallenge.getAuthenticationResult();

             userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
             userSignInResponse.setIdToken(authenticationResult.getIdToken());
             userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
             userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
             userSignInResponse.setTokenType(authenticationResult.getTokenType());
        }
             catch (InvalidParameterException e) {
            	 String errormsg=e.getErrorMessage();
            	 msg.setMessage(errormsg);
               return ResponseEntity.ok(msg);
              }
             catch (Exception e) {
            	 String errormsg=e.getMessage();
            	 msg.setMessage(errormsg);
               return ResponseEntity.ok(msg);
               }
             return ResponseEntity.ok(userSignInResponse);
	}

	public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, 
			String userName) {
		final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
		SecretKeySpec signingKey = new SecretKeySpec(
				userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
				HMAC_SHA256_ALGORITHM);
		try {
			Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
			mac.init(signingKey);
			mac.update(userName.getBytes(StandardCharsets.UTF_8));
			byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
			return java.util.Base64.getEncoder().encodeToString(rawHmac);
		} catch (Exception e) {
			throw new RuntimeException("Error while calculating ");
		}
	}

}
