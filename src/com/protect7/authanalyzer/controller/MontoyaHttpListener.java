package com.protect7.authanalyzer.controller;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.RequestFilterContext;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.MontoyaFilterContextFactory;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public class MontoyaHttpListener implements HttpHandler {

	private final CurrentConfig config;

	public MontoyaHttpListener() {
		this.config = CurrentConfig.getCurrentConfig();
	}

	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
		return RequestToBeSentAction.continueWith(request);
	}

	@Override
	public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
		if (response == null || response.initiatingRequest() == null) {
			return ResponseReceivedAction.continueWith(response);
		}
		if (isFiltered(MontoyaFilterContextFactory.from(response.toolSource() == null ? 0 : burp.LegacyToolMapper.toLegacyToolFlag(response.toolSource()), response.initiatingRequest(), response))) {
			return ResponseReceivedAction.continueWith(response);
		}
		CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(
			response.initiatingRequest(),
			response,
			response.toolSource() == null ? 0 : burp.LegacyToolMapper.toLegacyToolFlag(response.toolSource())
		);
		return ResponseReceivedAction.continueWith(response);
	}

	private boolean isFiltered(RequestFilterContext context) {
		for (int i = 0; i < config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if (filter.filterRequest(context)) {
				return true;
			}
		}
		return false;
	}
}
