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

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public abstract class AbstractReactivePrincipalSessionRegistry {

	private final ReactiveMaximumSessionsExceededHandler maximumSessionsExceededHandler;

	protected AbstractReactivePrincipalSessionRegistry(
			ReactiveMaximumSessionsExceededHandler maximumSessionsExceededHandler) {
		this.maximumSessionsExceededHandler = maximumSessionsExceededHandler;
	}

	public abstract Flux<ReactiveSessionInformation> getPrincipalSessions(Object principal);

	public abstract Mono<ReactiveSessionInformation> removeSessionInformation(String sessionId);

	public abstract Mono<ReactiveSessionInformation> updateLastAccessTime(String sessionId);

	public abstract Mono<Void> saveSessionInformation(ReactiveSessionInformation sessionInformation);

	public Mono<Void> checkAndSave(ReactiveSessionInformation sessionInformation, int maxSessions) {
		return checkCanSave(sessionInformation, maxSessions).then(Mono.defer(() -> saveSessionInformation(sessionInformation)));
	}

	private Mono<Void> checkCanSave(ReactiveSessionInformation sessionInformation, int maxSessions) {
		return getPrincipalSessions(sessionInformation.getPrincipal()).collectList().flatMap((registeredSessions) -> {
			int sessionsCount = registeredSessions.size();
			if (sessionsCount < maxSessions) {
				return Mono.empty();
			}
			if (sessionsCount == maxSessions) {
				for (ReactiveSessionInformation registeredSession : registeredSessions) {
					if (registeredSession.getSessionId().equals(sessionInformation.getSessionId())) {
						return Mono.empty();
					}
				}
			}
			return this.maximumSessionsExceededHandler
				.handle(new MaximumSessionsContext(sessionInformation, registeredSessions, maxSessions));
		});
	}

}
