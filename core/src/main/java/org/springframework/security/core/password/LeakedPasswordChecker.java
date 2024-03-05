/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.core.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * @see <a href="https://www.haveibeenpwned.com/API/v3#PwnedPasswords">Have I Been Pwned
 * API Docs</a>
 */
public final class LeakedPasswordChecker implements PasswordChecker {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String API_URL = "https://api.pwnedpasswords.com/range/";

	private final static int PREFIX_LENGTH = 5;

	private final MessageDigest sha1Digest;

	private RestClient restClient = RestClient.builder().baseUrl(API_URL).build();

	public LeakedPasswordChecker() {
		this.sha1Digest = getSha1Digest();
	}

	@Override
	public void check(String password, @Nullable String username) {
		byte[] hash = this.sha1Digest.digest(password.getBytes(StandardCharsets.UTF_8));
		String encoded = new String(Hex.encode(hash)).toUpperCase();
		String prefix = encoded.substring(0, PREFIX_LENGTH);
		String suffix = encoded.substring(PREFIX_LENGTH);

		List<String> passwords = getLeakedPasswordsForPrefix(prefix);
		LeakedPassword leakedPassword = findLeakedPassword(passwords, suffix);
		if (leakedPassword != null) {
			throw new LeakedPasswordException("The provided password has appeared " + leakedPassword.leakCount()
					+ " times in previous data breaches");
		}
	}

	public void setRestClient(RestClient restClient) {
		Assert.notNull(restClient, "restClient cannot be null");
		this.restClient = restClient;
	}

	private LeakedPassword findLeakedPassword(List<String> passwords, String suffix) {
		for (String pw : passwords) {
			if (pw.startsWith(suffix)) {
				return LeakedPassword.from(pw);
			}
		}
		return null;
	}

	private List<String> getLeakedPasswordsForPrefix(String prefix) {
		try {
			String response = this.restClient.get().uri(prefix).retrieve().body(String.class);
			if (!StringUtils.hasText(response)) {
				return Collections.emptyList();
			}
			return response.lines().toList();
		}
		catch (RestClientException ex) {
			this.logger.error("Request for leaked passwords failed", ex);
			return Collections.emptyList();
		}
	}

	private record LeakedPassword(String suffix, long leakCount) {

		static LeakedPassword from(String passwordLine) {
			String[] parts = passwordLine.split(":");
			return new LeakedPassword(parts[0], Long.parseLong(parts[1]));
		}

	}

	private static MessageDigest getSha1Digest() {
		try {
			return MessageDigest.getInstance("SHA-1");
		}
		catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex.getMessage());
		}
	}

}
