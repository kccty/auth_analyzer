package burp;

import com.protect7.authanalyzer.controller.HttpListener;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

final class MontoyaHttpHandlerBridge implements HttpHandler {

	private final HttpListener legacyListener;

	MontoyaHttpHandlerBridge(HttpListener legacyListener) {
		this.legacyListener = legacyListener;
	}

	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
		legacyListener.processHttpMessage(
			LegacyToolMapper.toLegacyToolFlag(request.toolSource()),
			true,
			new MontoyaHttpRequestResponseAdapter(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null)));
		return RequestToBeSentAction.continueWith(request);
	}

	@Override
	public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
		legacyListener.processHttpMessage(
			LegacyToolMapper.toLegacyToolFlag(response.toolSource()),
			false,
			new MontoyaHttpRequestResponseAdapter(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(response.initiatingRequest(), response)));
		return ResponseReceivedAction.continueWith(response);
	}
}
