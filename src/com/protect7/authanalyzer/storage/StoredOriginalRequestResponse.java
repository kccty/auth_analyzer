package com.protect7.authanalyzer.storage;

public class StoredOriginalRequestResponse {

	private final int id;
	private final StoredHttpMessage message;
	private final String method;
	private final String url;
	private final String infoText;
	private final String comment;
	private final int statusCode;
	private final int responseContentLength;
	private final boolean marked;

	public StoredOriginalRequestResponse(int id, StoredHttpMessage message, String method, String url, String infoText,
			String comment, int statusCode, int responseContentLength, boolean marked) {
		this.id = id;
		this.message = message;
		this.method = method;
		this.url = url;
		this.infoText = infoText;
		this.comment = comment;
		this.statusCode = statusCode;
		this.responseContentLength = responseContentLength;
		this.marked = marked;
	}

	public int getId() {
		return id;
	}

	public StoredHttpMessage getMessage() {
		return message;
	}

	public String getMethod() {
		return method;
	}

	public String getUrl() {
		return url;
	}

	public String getInfoText() {
		return infoText;
	}

	public String getComment() {
		return comment;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public int getResponseContentLength() {
		return responseContentLength;
	}

	public boolean isMarked() {
		return marked;
	}
}
