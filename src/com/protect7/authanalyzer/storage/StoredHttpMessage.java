package com.protect7.authanalyzer.storage;

public class StoredHttpMessage {

	private final String host;
	private final int port;
	private final boolean https;
	private final byte[] request;
	private final byte[] response;

	public StoredHttpMessage(String host, int port, boolean https, byte[] request, byte[] response) {
		this.host = host;
		this.port = port;
		this.https = https;
		this.request = request;
		this.response = response;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public boolean isHttps() {
		return https;
	}

	public byte[] getRequest() {
		return request;
	}

	public byte[] getResponse() {
		return response;
	}
}
