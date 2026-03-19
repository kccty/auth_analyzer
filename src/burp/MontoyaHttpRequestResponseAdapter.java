package burp;

import burp.api.montoya.http.message.HttpRequestResponse;

public class MontoyaHttpRequestResponseAdapter implements IHttpRequestResponse {
	private burp.api.montoya.http.HttpService montoyaService;
	private byte[] request;
	private byte[] response;
	private String comment;
	private String highlight;

	public MontoyaHttpRequestResponseAdapter(HttpRequestResponse rr) {
		this.montoyaService = rr.httpService();
		this.request = rr.request() == null ? null : rr.request().toByteArray().getBytes();
		this.response = rr.response() == null ? null : rr.response().toByteArray().getBytes();
	}

	public MontoyaHttpRequestResponseAdapter(burp.api.montoya.http.HttpService service, byte[] request, byte[] response) {
		this.montoyaService = service;
		this.request = request;
		this.response = response;
	}

	@Override public byte[] getRequest() { return request; }
	@Override public void setRequest(byte[] message) { this.request = message; }
	@Override public byte[] getResponse() { return response; }
	@Override public void setResponse(byte[] message) { this.response = message; }
	@Override public String getComment() { return comment; }
	@Override public void setComment(String comment) { this.comment = comment; }
	@Override public String getHighlight() { return highlight; }
	@Override public void setHighlight(String color) { this.highlight = color; }
	@Override public IHttpService getHttpService() { return new LegacyHelpersAdapter.SimpleHttpService(montoyaService.host(), montoyaService.port(), montoyaService.secure() ? "https" : "http"); }
	@Override public void setHttpService(IHttpService httpService) { this.montoyaService = burp.api.montoya.http.HttpService.httpService(httpService.getHost(), httpService.getPort(), "https".equalsIgnoreCase(httpService.getProtocol())); }
}
