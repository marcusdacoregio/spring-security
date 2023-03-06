/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.jackson2;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * A {@link JsonDeserializer} for {@link Saml2LogoutRequest}.
 *
 * @author Marcus da Coregio
 * @since 6.1
 */
public class Saml2LogoutRequestDeserializer extends JsonDeserializer<Saml2LogoutRequest> {

	@Override
	public Saml2LogoutRequest deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode logoutRequestNode = mapper.readTree(parser);
		String location = JsonNodeUtils.findStringValue(logoutRequestNode, "location");
		String bindingValue = JsonNodeUtils.findStringValue(logoutRequestNode, "binding");
		Saml2MessageBinding binding = Saml2MessageBinding.valueOf(bindingValue);
		Map<String, String> parameters = JsonNodeUtils.findValue(logoutRequestNode, "parameters", JsonNodeUtils.STRING_STRING_MAP, mapper);
		String id = JsonNodeUtils.findStringValue(logoutRequestNode, "id");
		String relyingPartyRegistrationId = JsonNodeUtils.findStringValue(logoutRequestNode, "relyingPartyRegistrationId");
		return Saml2LogoutRequest.builder()
				.id(id)
				.location(location)
				.binding(binding)
				.parameters((params) -> params.putAll(parameters))
				.relyingPartyRegistrationId(relyingPartyRegistrationId).build();
	}

}
