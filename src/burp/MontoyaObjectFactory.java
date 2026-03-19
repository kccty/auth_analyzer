package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

final class MontoyaObjectFactory {

	private MontoyaObjectFactory() {}

	static IRequestInfo requestInfo(HttpRequest request) {
		return new IRequestInfo() {
			@Override public String getMethod() { return request.method(); }
			@Override public URL getUrl() {
				try { return new URL(request.url()); } catch (MalformedURLException e) { throw new IllegalStateException(e); }
			}
			@Override public List<String> getHeaders() {
				List<String> headers = new ArrayList<String>();
				for (HttpHeader header : request.headers()) headers.add(header.toString());
				return headers;
			}
			@Override public List<IParameter> getParameters() {
				List<IParameter> out = new ArrayList<IParameter>();
				for (ParsedHttpParameter p : request.parameters()) out.add(parameter(p.name(), p.value(), mapType(p.type())));
				return out;
			}
			@Override public int getBodyOffset() { return request.bodyOffset(); }
			@Override public byte getContentType() {
				switch (request.contentType()) {
					case URL_ENCODED: return CONTENT_TYPE_URL_ENCODED;
					case MULTIPART: return CONTENT_TYPE_MULTIPART;
					case JSON: return CONTENT_TYPE_JSON;
					case XML: return CONTENT_TYPE_XML;
					case AMF: return CONTENT_TYPE_AMF;
					default: return CONTENT_TYPE_UNKNOWN;
				}
			}
		};
	}

	static IResponseInfo responseInfo(HttpResponse response) {
		return new IResponseInfo() {
			@Override public short getStatusCode() { return response.statusCode(); }
			@Override public List<String> getHeaders() {
				List<String> headers = new ArrayList<String>();
				for (HttpHeader header : response.headers()) headers.add(header.toString());
				return headers;
			}
			@Override public int getBodyOffset() { return response.bodyOffset(); }
			@Override public List<ICookie> getCookies() {
				List<ICookie> cookies = new ArrayList<ICookie>();
				response.cookies().forEach(c -> cookies.add(cookie(c.name(), c.value(), c.domain(), c.path(), c.expiration().orElse(null))));
				return cookies;
			}
			@Override public String getStatedMimeType() { return String.valueOf(response.statedMimeType()); }
			@Override public String getInferredMimeType() { return String.valueOf(response.inferredMimeType()); }
		};
	}

	static IParameter parameter(String name, String value, byte type) {
		return new IParameter() {
			@Override public byte getType() { return type; }
			@Override public String getName() { return name; }
			@Override public String getValue() { return value; }
			@Override public int getNameStart() { return -1; }
			@Override public int getNameEnd() { return -1; }
			@Override public int getValueStart() { return -1; }
			@Override public int getValueEnd() { return -1; }
		};
	}

	static ICookie cookie(String name, String value, String domain, String path, java.time.ZonedDateTime expiration) {
		final java.util.Date expires = expiration == null ? null : java.util.Date.from(expiration.toInstant());
		return new ICookie() {
			@Override public String getDomain() { return domain; }
			@Override public String getPath() { return path; }
			@Override public java.util.Date getExpiration() { return expires; }
			@Override public String getName() { return name; }
			@Override public String getValue() { return value; }
		};
	}

	static byte mapType(HttpParameterType type) {
		if (type == HttpParameterType.URL) return IParameter.PARAM_URL;
		if (type == HttpParameterType.BODY) return IParameter.PARAM_BODY;
		if (type == HttpParameterType.COOKIE) return IParameter.PARAM_COOKIE;
		if (type == HttpParameterType.JSON) return IParameter.PARAM_JSON;
		if (type == HttpParameterType.XML) return IParameter.PARAM_XML;
		if (type == HttpParameterType.XML_ATTRIBUTE) return IParameter.PARAM_XML_ATTR;
		if (type == HttpParameterType.MULTIPART_ATTRIBUTE) return IParameter.PARAM_MULTIPART_ATTR;
		return IParameter.PARAM_BODY;
	}

	static HttpParameterType mapType(byte type) {
		switch (type) {
			case IParameter.PARAM_URL: return HttpParameterType.URL;
			case IParameter.PARAM_BODY: return HttpParameterType.BODY;
			case IParameter.PARAM_COOKIE: return HttpParameterType.COOKIE;
			case IParameter.PARAM_JSON: return HttpParameterType.JSON;
			case IParameter.PARAM_XML: return HttpParameterType.XML;
			case IParameter.PARAM_XML_ATTR: return HttpParameterType.XML_ATTRIBUTE;
			case IParameter.PARAM_MULTIPART_ATTR: return HttpParameterType.MULTIPART_ATTRIBUTE;
			default: return HttpParameterType.BODY;
		}
	}
}
