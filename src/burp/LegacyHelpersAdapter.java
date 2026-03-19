package burp;

import java.net.URL;
import java.util.Base64;
import java.util.List;

public class LegacyHelpersAdapter implements IExtensionHelpers {

	@Override
	public IRequestInfo analyzeRequest(IHttpRequestResponse request) { throw unsupported(); }
	@Override
	public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) { throw unsupported(); }
	@Override
	public IRequestInfo analyzeRequest(byte[] request) { throw unsupported(); }
	@Override
	public IResponseInfo analyzeResponse(byte[] response) { throw unsupported(); }
	@Override
	public IParameter getRequestParameter(byte[] request, String parameterName) { throw unsupported(); }
	@Override
	public String urlDecode(String data) { return java.net.URLDecoder.decode(data, java.nio.charset.StandardCharsets.UTF_8); }
	@Override
	public String urlEncode(String data) { return java.net.URLEncoder.encode(data, java.nio.charset.StandardCharsets.UTF_8); }
	@Override
	public byte[] urlDecode(byte[] data) { return urlDecode(new String(data, java.nio.charset.StandardCharsets.UTF_8)).getBytes(java.nio.charset.StandardCharsets.UTF_8); }
	@Override
	public byte[] urlEncode(byte[] data) { return urlEncode(new String(data, java.nio.charset.StandardCharsets.UTF_8)).getBytes(java.nio.charset.StandardCharsets.UTF_8); }
	@Override
	public byte[] base64Decode(String data) { return Base64.getDecoder().decode(data); }
	@Override
	public byte[] base64Decode(byte[] data) { return Base64.getDecoder().decode(data); }
	@Override
	public String base64Encode(String data) { return Base64.getEncoder().encodeToString(data.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
	@Override
	public String base64Encode(byte[] data) { return Base64.getEncoder().encodeToString(data); }
	@Override
	public byte[] stringToBytes(String data) { return data == null ? null : data.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1); }
	@Override
	public String bytesToString(byte[] data) { return data == null ? null : new String(data, java.nio.charset.StandardCharsets.ISO_8859_1); }
	@Override
	public int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
		if (data == null || pattern == null || pattern.length == 0) return -1;
		int end = Math.min(to, data.length - pattern.length + 1);
		for (int i = Math.max(0, from); i < end; i++) {
			boolean ok = true;
			for (int j = 0; j < pattern.length; j++) {
				byte a = data[i + j];
				byte b = pattern[j];
				if (caseSensitive) {
					if (a != b) { ok = false; break; }
				} else if (Character.toLowerCase((char) a) != Character.toLowerCase((char) b)) {
					ok = false; break;
				}
			}
			if (ok) return i;
		}
		return -1;
	}
	@Override
	public byte[] buildHttpMessage(List<String> headers, byte[] body) {
		StringBuilder sb = new StringBuilder();
		for (String h : headers) sb.append(h).append("\r\n");
		sb.append("\r\n");
		byte[] head = sb.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
		byte[] out = new byte[head.length + (body == null ? 0 : body.length)];
		System.arraycopy(head, 0, out, 0, head.length);
		if (body != null) System.arraycopy(body, 0, out, head.length, body.length);
		return out;
	}
	@Override
	public byte[] buildHttpRequest(URL url) { throw unsupported(); }
	@Override
	public byte[] addParameter(byte[] request, IParameter parameter) { throw unsupported(); }
	@Override
	public byte[] removeParameter(byte[] request, IParameter parameter) { throw unsupported(); }
	@Override
	public byte[] updateParameter(byte[] request, IParameter parameter) { throw unsupported(); }
	@Override
	public byte[] toggleRequestMethod(byte[] request) { throw unsupported(); }
	@Override
	public IHttpService buildHttpService(String host, int port, String protocol) { return new SimpleHttpService(host, port, protocol); }
	@Override
	public IHttpService buildHttpService(String host, int port, boolean useHttps) { return new SimpleHttpService(host, port, useHttps ? "https" : "http"); }
	@Override
	public IParameter buildParameter(String name, String value, byte type) { throw unsupported(); }
	@Override
	public IHttpHeader buildHeader(String name, String value) { throw unsupported(); }
	@Override
	public IScannerInsertionPoint makeScannerInsertionPoint(String name, byte[] baseRequest, int from, int to) { throw unsupported(); }
	@Override
	public IResponseVariations analyzeResponseVariations(byte[]... responses) { throw unsupported(); }
	@Override
	public IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses) { throw unsupported(); }

	private UnsupportedOperationException unsupported() {
		return new UnsupportedOperationException("Not implemented in Montoya single-entry test mode");
	}

	private static class SimpleHttpService implements IHttpService {
		private final String host;
		private final int port;
		private final String protocol;
		SimpleHttpService(String host, int port, String protocol) {
			this.host = host;
			this.port = port;
			this.protocol = protocol;
		}
		@Override public String getHost() { return host; }
		@Override public int getPort() { return port; }
		@Override public String getProtocol() { return protocol; }
	}
}
