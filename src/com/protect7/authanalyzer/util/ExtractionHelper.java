package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenBuilder;
import com.protect7.authanalyzer.entities.TokenLocation;
import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.responses.HttpResponse;

public class ExtractionHelper {

	public static boolean extractCurrentTokenValue(HttpResponse sessionResponse, Token token) {
		if (sessionResponse == null) {
			return false;
		}
		if(token.doAutoExtractAtLocation(AutoExtractLocation.COOKIE)) {
			sessionResponse.cookies().forEach(cookie -> {
				if (cookie.name().equals(token.getExtractName())) {
					token.setValue(cookie.value());
				}
			});
			if (token.getValue() != null) {
				return true;
			}
		}
		String statedMimeType = sessionResponse.statedMimeType() == null ? "" : String.valueOf(sessionResponse.statedMimeType());
		String inferredMimeType = sessionResponse.inferredMimeType() == null ? "" : String.valueOf(sessionResponse.inferredMimeType());
		if (token.doAutoExtractAtLocation(AutoExtractLocation.HTML) && (statedMimeType.equals("HTML") || inferredMimeType.equals("HTML"))) {
			try {
				String bodyAsString = sessionResponse.bodyToString();
				String value = getTokenValueFromInputField(bodyAsString, token.getExtractName());
				if (value != null) {
					token.setValue(value);
					return true;
				}
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Can not parse HTML Response. Error Message: " + e.getMessage());
			}
		}
		if (token.doAutoExtractAtLocation(AutoExtractLocation.JSON) && (statedMimeType.equals("JSON") || inferredMimeType.equals("JSON"))) {
			JsonElement jsonElement = getBodyAsJson(sessionResponse);
			if(jsonElement != null) {
				String value = getJsonTokenValue(jsonElement, token);
				if (value != null) {
					token.setValue(value);
					return true;
				}
			}
		}
		return false;
	}


	public static String getTokenValueFromInputField(String document, String name) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", name);
		for(Element element : csrfFields) {
			String csrfValue = element.attr("value");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
			csrfValue = element.attr("content");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
		}
		return null;
	}

	public static boolean extractTokenWithFromToString(HttpResponse sessionResponse, Token token) {
		try {
			if (sessionResponse == null) {
				return false;
			}
			String statedMimeType = sessionResponse.statedMimeType() == null ? "" : String.valueOf(sessionResponse.statedMimeType()).toUpperCase();
			String inferredMimeType = sessionResponse.inferredMimeType() == null ? "" : String.valueOf(sessionResponse.inferredMimeType()).toUpperCase();
			boolean doExtract = token.doFromToExtractAtLocation(FromToExtractLocation.ALL);
			for(FromToExtractLocation locationType : FromToExtractLocation.values()) {
				if(locationType != FromToExtractLocation.ALL && locationType != FromToExtractLocation.HEADER && locationType != FromToExtractLocation.BODY) {
					if (token.doFromToExtractAtLocation(locationType) && (statedMimeType.equals(locationType.toString())
							|| inferredMimeType.equals(locationType.toString()))) {
						doExtract = true;
						break;
					}
				}
			}
			if(inferredMimeType.equals("") && statedMimeType.equals("")) {
				doExtract = true;
			}
			if(doExtract) {
				String responseAsString = null;
				if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = sessionResponse.toString();
				}
				else if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && !token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = sessionResponse.toString().substring(0, sessionResponse.bodyOffset());
				}
				else if(!token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = sessionResponse.bodyToString();
				}
				if(responseAsString != null) {
					int beginIndex = responseAsString.indexOf(token.getGrepFromString());
					if (beginIndex != -1) {
						beginIndex = beginIndex + token.getGrepFromString().length();
						String lineWithValue = responseAsString.substring(beginIndex).split("\n")[0];
						String value = null;
						if (token.getGrepToString().equals("")) {
							value = lineWithValue;
						} else if (lineWithValue.contains(token.getGrepToString())) {
							value = lineWithValue.substring(0, lineWithValue.indexOf(token.getGrepToString()));
						}
						if (value != null) {
							token.setValue(value);
							return true;
						}
					}
				}
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Can not extract from to value. Error Message: " + e.getMessage());
		}
		return false;
	}

	
	private static String getJsonTokenValue(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					return getJsonTokenValue(entry.getValue(), token);
				}
				if (entry.getValue().isJsonPrimitive()) {
					if (entry.getKey().equals(token.getExtractName())) {
						return entry.getValue().getAsString();
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonObject()) {
					return getJsonTokenValue(arrayJsonEl.getAsJsonObject(), token);
				}
			}
		}
		return null;
	}
	
	private static JsonElement getBodyAsJson(HttpResponse response) {
		try {
			String bodyAsString = response.bodyToString();
			JsonReader reader = new JsonReader(new StringReader(bodyAsString));
			reader.setLenient(true);
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement;
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Can not parse JSON Response. Error Message: " + e.getMessage());
		}
		return null;
	}

	
	public static ArrayList<Token> extractTokensFromMessages(java.util.List<HttpRequestResponse> messages) {
		HashMap<String, Token> tokenMap = new HashMap<String, Token>();
		String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
		String[] dynamicPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_DYNAMIC_PATTERNS);
		for(HttpRequestResponse message : messages) {
			if(message.request() != null) {
				for(ParsedHttpParameter param : message.request().parameters()) {
					boolean process = false;
					boolean isDynamic = false;
					for(String pattern : staticPatterns) {
						if(param.name().toLowerCase().contains(pattern)) {
							process = true;
							break;
						}
					}
					for(String pattern : dynamicPatterns) {
						if(param.name().toLowerCase().contains(pattern)) {
							process = true;
							isDynamic = true;
							break;
						}
					}
					if(process) {
						boolean autoExtract = isDynamic;
						if(tokenMap.containsKey(param.name())) {
							autoExtract = tokenMap.get(param.name()).isAutoExtract();
						}
						Token token = null;
						String urlDecodedName;
						try {
							urlDecodedName = URLDecoder.decode(param.name(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedName = param.name();
						}
						String urlDecodedValue;
						try {
							urlDecodedValue = URLDecoder.decode(param.value(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedValue = param.value();
						}
						if(param.type() == HttpParameterType.COOKIE) {
							token = new TokenBuilder().setName(urlDecodedName)
								.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
								.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
								.setValue(param.value()).setExtractName(param.name())
								.setIsAutoExtract(true).build();
						}
						if(param.type() == HttpParameterType.URL) {
							token = new TokenBuilder().setName(urlDecodedName)
								.setTokenLocationSet(EnumSet.of(TokenLocation.URL))
								.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
								.setValue(urlDecodedValue).setExtractName(urlDecodedName)
								.setIsAutoExtract(autoExtract).setIsStaticValue(!autoExtract).build();
						}
						if(param.type() == HttpParameterType.BODY) {
							token = new TokenBuilder().setName(urlDecodedName)
								.setTokenLocationSet(EnumSet.of(TokenLocation.BODY))
								.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
								.setValue(urlDecodedValue).setExtractName(urlDecodedName)
								.setIsAutoExtract(autoExtract).setIsStaticValue(!autoExtract).build();
						}
						if(param.type() == HttpParameterType.JSON) {
							token = new TokenBuilder().setName(urlDecodedName)
								.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
								.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
								.setValue(urlDecodedValue).setExtractName(urlDecodedName)
								.setIsAutoExtract(autoExtract).setIsStaticValue(!autoExtract).build();
						}
						if(token != null) {
							tokenMap.put(token.getName(), token);
						}
					}
				}
			}
			if(message.response() != null) {
				for (burp.api.montoya.http.message.Cookie cookie : message.response().cookies()) {
					Token token = new TokenBuilder().setName(cookie.name())
						.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
						.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
						.setExtractName(cookie.name()).setIsAutoExtract(true).build();
					tokenMap.put(token.getName(), token);
				}
				String stated = message.response().statedMimeType() == null ? "" : String.valueOf(message.response().statedMimeType());
				String inferred = message.response().inferredMimeType() == null ? "" : String.valueOf(message.response().inferredMimeType());
				if(stated.equals("JSON") || inferred.equals("JSON")) {
					JsonElement jsonElement = getBodyAsJson(message.response());
					if(jsonElement != null) {
						createTokensFromJson(jsonElement, tokenMap);
					}
				}
			}
		}
		ArrayList<Token> tokenList = new ArrayList<Token>(tokenMap.values());
		tokenList.sort(Comparator.comparing(Token::sortString));
		return tokenList;
	}
	
	private static void createTokensFromJson(JsonElement jsonElement, HashMap<String, Token> tokenMap) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					createTokensFromJson(jsonElement, tokenMap);
				}
				if (entry.getValue().isJsonPrimitive()) {
					String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
					for(String pattern : staticPatterns) {
						if(entry.getKey().toLowerCase().contains(pattern)) {
							Token token = new TokenBuilder()
									.setName(entry.getKey())
									.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
									.setExtractName(entry.getKey())
									.setIsAutoExtract(true)
									.build();
							tokenMap.put(token.getName(), token);
							break;
						}
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonObject()) {
					createTokensFromJson(jsonElement, tokenMap);
				}
			}
		}
	}
}
