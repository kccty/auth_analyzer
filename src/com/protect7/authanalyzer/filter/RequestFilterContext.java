package com.protect7.authanalyzer.filter;

public class RequestFilterContext {
	private final int toolFlag;
	private final String url;
	private final String path;
	private final String query;
	private final String method;
	private final String inferredMimeType;
	private final Short statusCode;
	private final boolean inScope;

	public RequestFilterContext(int toolFlag, String url, String path, String query, String method,
			String inferredMimeType, Short statusCode, boolean inScope) {
		this.toolFlag = toolFlag;
		this.url = url;
		this.path = path;
		this.query = query;
		this.method = method;
		this.inferredMimeType = inferredMimeType;
		this.statusCode = statusCode;
		this.inScope = inScope;
	}

	public int getToolFlag() {
		return toolFlag;
	}

	public String getUrl() {
		return url;
	}

	public String getPath() {
		return path;
	}

	public String getQuery() {
		return query;
	}

	public String getMethod() {
		return method;
	}

	public String getInferredMimeType() {
		return inferredMimeType;
	}

	public Short getStatusCode() {
		return statusCode;
	}

	public boolean isInScope() {
		return inScope;
	}
}
