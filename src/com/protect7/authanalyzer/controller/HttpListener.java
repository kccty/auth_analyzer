package com.protect7.authanalyzer.controller;

import java.net.URL;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.RequestFilterContext;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if(config.isRunning() && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {		
			if(!isFiltered(toolFlag, messageInfo)) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}
	
	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		RequestFilterContext context = buildFilterContext(toolFlag, messageInfo);
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(context)) {
				return true;
			}
		}
		return false;
	}

	private RequestFilterContext buildFilterContext(int toolFlag, IHttpRequestResponse messageInfo) {
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		URL url = requestInfo.getUrl();
		String urlString = url == null ? null : url.toString();
		String path = url == null ? null : url.getPath();
		String query = url == null ? null : url.getQuery();
		String inferredMimeType = responseInfo == null ? null : responseInfo.getInferredMimeType();
		Short statusCode = responseInfo == null ? null : responseInfo.getStatusCode();
		boolean inScope = url != null && BurpExtender.callbacks.isInScope(url);
		return new RequestFilterContext(toolFlag, urlString, path, query, requestInfo.getMethod(), inferredMimeType, statusCode, inScope);
	}
}
