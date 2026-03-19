package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.List;

import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.entities.TokenPriority;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class MontoyaRequestBuilder {

	private MontoyaRequestBuilder() {}

	public static HttpRequest applySession(HttpRequest request, Session session, TokenPriority tokenPriority) {
		if (request == null) {
			return null;
		}
		HttpRequest modified = request;
		if (session.isTestCors()) {
			modified = modified.withMethod("OPTIONS");
		}
		modified = applyHeaderChanges(modified, session);
		modified = applyParameterChanges(modified, session, tokenPriority);
		return modified;
	}

	private static HttpRequest applyHeaderChanges(HttpRequest request, Session session) {
		HttpRequest modified = request;
		if(session.isRemoveHeaders()) {
			String[] headersToRemoveSplit = session.getHeadersToRemove().replace("\r", "").split("\n");
			for (String header : headersToRemoveSplit) {
				if (header.contains(":")) {
					modified = modified.withRemovedHeader(header.split(":")[0]);
				}
			}
		}
		for (String headerToReplace : RequestModifHelper.getHeaderToReplaceList(session)) {
			int keyIndex = headerToReplace.indexOf(":");
			if (keyIndex != -1) {
				String headerKey = headerToReplace.substring(0, keyIndex).trim();
				String headerValue = headerToReplace.substring(keyIndex + 1).trim();
				modified = modified.withUpdatedHeader(headerKey, headerValue);
			}
		}
		return modified;
	}

	private static HttpRequest applyParameterChanges(HttpRequest request, Session session, TokenPriority tokenPriority) {
		HttpRequest modified = request;
		for (Token token : session.getTokens()) {
			if (token.getValue() == null && !token.isRemove() && !token.isPromptForInput()) {
				continue;
			}
			modified = applyParameterToken(modified, token);
		}
		return modified;
	}

	private static HttpRequest applyParameterToken(HttpRequest request, Token token) {
		HttpRequest modified = request;
		if (token.doReplaceAtLocation(TokenLocation.URL)) {
			modified = updateParameters(modified, token, HttpParameterType.URL);
		}
		if (token.doReplaceAtLocation(TokenLocation.BODY)) {
			modified = updateParameters(modified, token, HttpParameterType.BODY);
		}
		if (token.doReplaceAtLocation(TokenLocation.COOKIE)) {
			modified = updateParameters(modified, token, HttpParameterType.COOKIE);
		}
		if (token.doReplaceAtLocation(TokenLocation.JSON)) {
			modified = updateParameters(modified, token, HttpParameterType.JSON);
		}
		return modified;
	}

	private static HttpRequest updateParameters(HttpRequest request, Token token, HttpParameterType type) {
		List<ParsedHttpParameter> matches = new ArrayList<ParsedHttpParameter>();
		for (ParsedHttpParameter parameter : request.parameters(type)) {
			boolean sameName = token.isCaseSensitiveTokenName()
				? parameter.name().equals(token.getName()) || parameter.name().equals(token.getUrlEncodedName())
				: parameter.name().equalsIgnoreCase(token.getName()) || parameter.name().equalsIgnoreCase(token.getUrlEncodedName());
			if (sameName) {
				matches.add(parameter);
			}
		}
		if (token.isRemove()) {
			if (!matches.isEmpty()) {
				return request.withRemovedParameters(matches);
			}
			return request;
		}
		HttpParameter newParameter = HttpParameter.parameter(token.getUrlEncodedName(), token.getValue(), type);
		if (!matches.isEmpty()) {
			return request.withUpdatedParameters(newParameter);
		}
		if (token.isAddIfNotExists()) {
			return request.withAddedParameters(newParameter);
		}
		return request;
	}
}
