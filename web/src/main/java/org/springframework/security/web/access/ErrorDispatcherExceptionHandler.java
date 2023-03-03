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

package org.springframework.security.web.access;

import java.io.IOException;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ErrorDispatcherExceptionHandler implements RequestDispatcherExceptionHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, RuntimeException exception)
			throws IOException {
		int statusCode = (int) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		String message = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
		response.sendError(statusCode, message);
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		return DispatcherType.ERROR == request.getDispatcherType();
	}

}
