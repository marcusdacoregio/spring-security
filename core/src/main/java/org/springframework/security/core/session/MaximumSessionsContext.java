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

package org.springframework.security.core.session;

import java.util.List;

public final class MaximumSessionsContext {

	private final ReactiveSessionInformation currentSession;

	private final List<ReactiveSessionInformation> registeredSessions;

	private final int maximumSessionsAllowed;

	public MaximumSessionsContext(ReactiveSessionInformation currentSession,
			List<ReactiveSessionInformation> registeredSessions, int maximumSessionsAllowed) {
		this.currentSession = currentSession;
		this.registeredSessions = registeredSessions;
		this.maximumSessionsAllowed = maximumSessionsAllowed;
	}

	public ReactiveSessionInformation getCurrentSession() {
		return this.currentSession;
	}

	public List<ReactiveSessionInformation> getRegisteredSessions() {
		return this.registeredSessions;
	}

	public int getMaximumSessionsAllowed() {
		return this.maximumSessionsAllowed;
	}

}
