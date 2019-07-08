/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.openid.connect.token;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.service.UserInfoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

@Service
public class ConnectTokenEnhancer implements TokenEnhancer {

	/**
	 * Logger for this class
	 */
	
	//大素数
	BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
	
	
	private static final Logger logger = LoggerFactory.getLogger(ConnectTokenEnhancer.class);

	@Autowired
	private ConfigurationPropertiesBean configBean;

	@Autowired
	private JWTSigningAndValidationService jwtService;

	@Autowired
	private ClientDetailsEntityService clientService;

	@Autowired
	private UserInfoService userInfoService;

	@Autowired
	private OIDCTokenService connectTokenService;

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,	OAuth2Authentication authentication) {
		
		
		logger.info("token test");
		OAuth2AccessTokenEntity token = (OAuth2AccessTokenEntity) accessToken;
		OAuth2Request originalAuthRequest = authentication.getOAuth2Request();

		String clientId = originalAuthRequest.getClientId();
		ClientDetailsEntity client = clientService.loadClientByClientId(clientId);

		Builder builder = new JWTClaimsSet.Builder()
				.claim("azp", clientId)
				.issuer(configBean.getIssuer())
				.issueTime(new Date())
				.expirationTime(token.getExpiration())
				.subject(authentication.getName())
				.jwtID(UUID.randomUUID().toString()); // set a random NONCE in the middle of it

		String audience = (String) authentication.getOAuth2Request().getExtensions().get("aud");
		if (!Strings.isNullOrEmpty(audience)) {
			builder.audience(Lists.newArrayList(audience));
		}

		addCustomAccessTokenClaims(builder, token, authentication);

		JWTClaimsSet claims = builder.build();

		JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();
		JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null, null,
				jwtService.getDefaultSignerKeyId(),
				null, null);
		SignedJWT signed = new SignedJWT(header, claims);

		jwtService.signJwt(signed);

		token.setJwt(signed);

		/**
		 * Authorization request scope MUST include "openid" in OIDC, but access token request
		 * may or may not include the scope parameter. As long as the AuthorizationRequest
		 * has the proper scope, we can consider this a valid OpenID Connect request. Otherwise,
		 * we consider it to be a vanilla OAuth2 request.
		 *
		 * Also, there must be a user authentication involved in the request for it to be considered
		 * OIDC and not OAuth, so we check for that as well.
		 */
		if (originalAuthRequest.getScope().contains(SystemScopeService.OPENID_SCOPE)
				&& !authentication.isClientOnly()) {
			

			String username = authentication.getName();
			UserInfo userInfo = userInfoService.getByUsernameAndClientId(username, clientId);

			if (userInfo != null) {

				
				//String sub = createRPSub(userInfo.getSub(), clientId);
				
				String uid = "8515918516694561415648484561456158645613484613348118648451684148645154815184151816156489486156184586413311848445151845121846654846123156486";
				String sub = new BigInteger(clientId).modPow(new BigInteger(uid), P).toString();
						//createRPSub(clientId, "8515918516694561415648484561456158645613484613348118648451684148645154815184151816156489486156184586413311848445151845121846654846123156486");
				
//				String sub = userInfo.getSub();
				
				
				JWT idToken = connectTokenService.createIdToken(client,
						originalAuthRequest, claims.getIssueTime(),
						sub, token);
				
				// attach the id token to the parent access token
				token.setIdToken(idToken);
				
			} else {
				// can't create an id token if we can't find the user
				logger.warn("Request for ID token when no user is present.");
			}
		}

		return token;
	}

	public ConfigurationPropertiesBean getConfigBean() {
		return configBean;
	}

	public void setConfigBean(ConfigurationPropertiesBean configBean) {
		this.configBean = configBean;
	}

	public JWTSigningAndValidationService getJwtService() {
		return jwtService;
	}

	public void setJwtService(JWTSigningAndValidationService jwtService) {
		this.jwtService = jwtService;
	}

	public ClientDetailsEntityService getClientService() {
		return clientService;
	}

	public void setClientService(ClientDetailsEntityService clientService) {
		this.clientService = clientService;
	}


	/**
	 * Hook for subclasses that allows adding custom claims to the JWT that will be used as access token.
	 * @param builder the builder holding the current claims
	 * @param token the un-enhanced token
	 * @param authentication current authentication
	 */
    protected void addCustomAccessTokenClaims(JWTClaimsSet.Builder builder, OAuth2AccessTokenEntity token,
	    OAuth2Authentication authentication) {
	}
    
    private String createRPSub(String originSub, String client_id){
    	BigInteger uid = new BigInteger(originSub);
    	BigInteger clientId = new BigInteger(client_id);
    	BigInteger temp = new BigInteger("1");
    	while(clientId.compareTo(new BigInteger("0")) > 0){
    		if(clientId.testBit(0)){
    			temp = temp.multiply(uid).mod(P);
    		}
    		uid = uid.multiply(uid).mod(P);
    		clientId = clientId.shiftRight(1);
    	}
    	return temp.toString();
    }

}
