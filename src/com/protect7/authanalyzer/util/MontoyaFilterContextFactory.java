package com.protect7.authanalyzer.util;

import com.protect7.authanalyzer.filter.RequestFilterContext;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class MontoyaFilterContextFactory {

	private MontoyaFilterContextFactory() {}

	public static RequestFilterContext from(int toolFlag, HttpRequest request, HttpResponse response) {
		String inferredMimeType = response == null || response.inferredMimeType() == null ? null : String.valueOf(response.inferredMimeType());
		Short statusCode = response == null ? null : (short) response.statusCode();
		return new RequestFilterContext(
			toolFlag,
			request == null ? null : request.url(),
			request == null ? null : request.pathWithoutQuery(),
			request == null ? null : request.query(),
			request == null ? null : request.method(),
			inferredMimeType,
			statusCode,
			request != null && request.isInScope()
		);
	}
}
