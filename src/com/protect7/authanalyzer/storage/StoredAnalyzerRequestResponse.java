package com.protect7.authanalyzer.storage;

public class StoredAnalyzerRequestResponse {

	private final StoredHttpMessage message;
	private final String status;
	private final String infoText;
	private final int statusCode;
	private final int responseContentLength;

	public StoredAnalyzerRequestResponse(StoredHttpMessage message, String status, String infoText, int statusCode,
			int responseContentLength) {
		this.message = message;
		this.status = status;
		this.infoText = infoText;
		this.statusCode = statusCode;
		this.responseContentLength = responseContentLength;
	}

	public StoredHttpMessage getMessage() {
		return message;
	}

	public String getStatus() {
		return status;
	}

	public String getInfoText() {
		return infoText;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public int getResponseContentLength() {
		return responseContentLength;
	}
}
