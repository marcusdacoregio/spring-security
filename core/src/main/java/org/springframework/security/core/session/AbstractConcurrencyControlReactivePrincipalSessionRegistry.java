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

import reactor.core.publisher.Mono;

import org.springframework.util.Assert;

/**
 * An abstract implementation of {@link ReactiveSessionRegistry} that applies concurrency
 * control on {@link #saveSessionInformation(ReactiveSessionInformation)}. If the provided
 * {@link ReactiveSessionInformation#getMaxSessionsAllowed()} is not null, then it will
 * check if the maximum sessions is exceeded and invoke the provided
 * {@link #maximumSessionsExceededHandler}.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public abstract class AbstractConcurrencyControlReactivePrincipalSessionRegistry implements ReactiveSessionRegistry {

	private final ReactiveMaximumSessionsExceededHandler maximumSessionsExceededHandler;

	protected AbstractConcurrencyControlReactivePrincipalSessionRegistry(
			ReactiveMaximumSessionsExceededHandler maximumSessionsExceededHandler) {
		Assert.notNull(maximumSessionsExceededHandler, "maximumSessionsExceededHandler cannot be null");
		this.maximumSessionsExceededHandler = maximumSessionsExceededHandler;
	}

	/**
	 * Applies concurrency control if the provided
	 * {@link ReactiveSessionInformation#getMaxSessionsAllowed()} is not null and then
	 * invokes {@link #save(ReactiveSessionInformation)}. If the maximum sessions is
	 * exceeded, then the {@link #maximumSessionsExceededHandler} is invoked.
	 * @param sessionInformation the {@link ReactiveSessionInformation} to save
	 * @return an empty {@link Mono} that completes when the session information is saved
	 */
	@Override
	public Mono<Void> saveSessionInformation(ReactiveSessionInformation sessionInformation) {
		if (sessionInformation.getMaxSessionsAllowed() == null) {
			return save(sessionInformation);
		}
		return getAllSessions(sessionInformation.getPrincipal()).collectList().flatMap((registeredSessions) -> {
			int sessionsCount = registeredSessions.size();
			if (sessionsCount < sessionInformation.getMaxSessionsAllowed()) {
				return Mono.empty();
			}
			if (sessionsCount == sessionInformation.getMaxSessionsAllowed()) {
				for (ReactiveSessionInformation registeredSession : registeredSessions) {
					if (registeredSession.getSessionId().equals(sessionInformation.getSessionId())) {
						return Mono.empty();
					}
				}
			}
			return this.maximumSessionsExceededHandler.handle(sessionInformation, registeredSessions);
		}).then(Mono.defer(() -> save(sessionInformation)));
	}

	protected abstract Mono<Void> save(ReactiveSessionInformation sessionInformation);

}
