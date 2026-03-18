package com.protect7.authanalyzer.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.storage.StoredAnalyzerRequestResponse;
import com.protect7.authanalyzer.storage.StoredHttpMessage;
import com.protect7.authanalyzer.storage.StoredOriginalRequestResponse;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

public class DataStorageProvider {

	private static final String SITEMAP_HOST = "authanalyzer.storage.local";
	private static final String SETTINGS_PATH = "/settings";
	private static final String INDEX_PATH = "/messages/index";
	private static final String ORIGINAL_BASE_PATH = "/messages/original/";
	private static final String SESSION_BASE_PATH = "/messages/session/";
	private static final IHttpService HTTPSERVICE = BurpExtender.callbacks.getHelpers().buildHttpService(SITEMAP_HOST, 443, true);
	private static final Gson GSON = new GsonBuilder().create();

	public static String getSetupAsJsonString() {
		JsonArray sessionArray = new JsonArray();
		for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			Gson gson = new GsonBuilder().setExclusionStrategies(session.getExclusionStrategy()).create();
			String sessionJsonAsString = gson.toJson(session);
			JsonObject sessionElement = JsonParser.parseString(sessionJsonAsString).getAsJsonObject();
			sessionElement.addProperty("name", session.getName());
			sessionArray.add(sessionElement);
		}

		JsonObject sessionsObject = new JsonObject();
		sessionsObject.add("sessions", sessionArray);

		JsonArray filterArray = new JsonArray();
		for (RequestFilter filter : CurrentConfig.getCurrentConfig().getRequestFilterList()) {
			JsonObject filterElement = JsonParser.parseString(filter.toJson()).getAsJsonObject();
			filterArray.add(filterElement);
		}
		sessionsObject.add("filters", filterArray);
		return sessionsObject.toString();
	}

	public static void saveSetup() {
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][save-setup] Persisting session/filter setup to sitemap storage");
		BurpExtender.callbacks.addToSiteMap(getSettingsMessage());
	}

	public static String loadSetup() {
		IHttpRequestResponse[] messages = BurpExtender.callbacks.getSiteMap(HTTPSERVICE.toString() + SETTINGS_PATH);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-setup] entries=" + messages.length);
		if (messages.length > 0) {
			for (int i = messages.length - 1; i >= 0; i--) {
				try {
					byte[] response = messages[i].getResponse();
					BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-setup] candidateIndex=" + i + " responseBytes=" + (response == null ? -1 : response.length));
					if (response != null && response.length > 0) {
						return new String(response);
					}
				} catch (Exception e) {
					BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-setup][error] candidateIndex=" + i + " msg=" + e.getMessage());
				}
			}
		}
		return null;
	}

	public static void saveMessage(int id, String session, IHttpRequestResponse message) {
		if (session == null) {
			saveOriginalRequestResponse(new StoredOriginalRequestResponse(id, toStoredHttpMessage(message), null, null, null, "", -1, -1, false));
		} else {
			saveSessionRequestResponse(session, id, new AnalyzerRequestResponse(message, BypassConstants.NA, null, -1, -1));
		}
	}

	public IHttpRequestResponse loadMessage(int id, String session) {
		if (session == null) {
			StoredOriginalRequestResponse stored = loadStoredOriginal(id);
			return stored == null ? null : toHttpRequestResponse(stored.getMessage());
		}
		StoredAnalyzerRequestResponse stored = loadStoredSession(session, id);
		return stored == null ? null : toHttpRequestResponse(stored.getMessage());
	}

	public static void saveOriginalRequestResponse(OriginalRequestResponse requestResponse) {
		if (requestResponse == null) {
			return;
		}
		StoredOriginalRequestResponse stored = new StoredOriginalRequestResponse(requestResponse.getId(),
				toStoredHttpMessage(requestResponse.getRequestResponse()), requestResponse.getMethod(), requestResponse.getUrl(),
				requestResponse.getInfoText(), requestResponse.getComment(), requestResponse.getStatusCode(),
				requestResponse.getResponseContentLength(), requestResponse.isMarked());
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][store-original] id=%d method=%s url=%s req=%d resp=%d",
				stored.getId(), stored.getMethod(), stored.getUrl(),
				stored.getMessage() == null || stored.getMessage().getRequest() == null ? -1 : stored.getMessage().getRequest().length,
				stored.getMessage() == null || stored.getMessage().getResponse() == null ? -1 : stored.getMessage().getResponse().length));
		saveOriginalRequestResponse(stored);
	}

	public static void saveSessionRequestResponse(String sessionName, int id, AnalyzerRequestResponse requestResponse) {
		if (sessionName == null || requestResponse == null) {
			return;
		}
		StoredAnalyzerRequestResponse stored = new StoredAnalyzerRequestResponse(toStoredHttpMessage(requestResponse.getRequestResponse()),
				requestResponse.getStatus() == null ? null : requestResponse.getStatus().name(), requestResponse.getInfoText(),
				requestResponse.getStatusCode(), requestResponse.getResponseContentLength());
		String path = getSessionPath(sessionName, id);
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][store-session] session=%s id=%d path=%s status=%s req=%d resp=%d info=%s",
				sessionName, id, path, stored.getStatus(),
				stored.getMessage() == null || stored.getMessage().getRequest() == null ? -1 : stored.getMessage().getRequest().length,
				stored.getMessage() == null || stored.getMessage().getResponse() == null ? -1 : stored.getMessage().getResponse().length,
				stored.getInfoText()));
		saveSessionRequestResponse(sessionName, id, stored);
	}
	
	public static void saveAllStoredMessages() {
		clearStoredMessages();
		CurrentConfig config = CurrentConfig.getCurrentConfig();
		for (OriginalRequestResponse requestResponse : config.getTableModel().getOriginalRequestResponseList()) {
			saveOriginalRequestResponse(requestResponse);
		}
		for (Session session : config.getSessions()) {
			for (Map.Entry<Integer, AnalyzerRequestResponse> entry : session.getRequestResponseMap().entrySet()) {
				saveSessionRequestResponse(session.getName(), entry.getKey(), entry.getValue());
			}
		}
	}

	public static void restoreStoredMessages() {
		StoredIndex index = loadIndex();
		if (index == null) {
			BurpExtender.callbacks.printOutput("[AuthAnalyzer][restore] index is null, nothing to restore");
			return;
		}
		CurrentConfig config = CurrentConfig.getCurrentConfig();
		ArrayList<Integer> originalIds = new ArrayList<Integer>(index.originalIds);
		Collections.sort(originalIds);
		int maxId = config.getMapId();
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][restore] start originalIds=%d sessionNames=%s currentMapId=%d",
				originalIds.size(), index.sessions.keySet(), config.getMapId()));
		for (Integer id : originalIds) {
			StoredOriginalRequestResponse stored = loadStoredOriginal(id);
			BurpExtender.callbacks.printOutput(String.format(
					"[AuthAnalyzer][restore-original] id=%d stored=%s message=%s",
					id, stored == null ? "null" : "ok", (stored == null || stored.getMessage() == null) ? "null" : "ok"));
			if (stored == null || stored.getMessage() == null) {
				continue;
			}
			IHttpRequestResponse message = toHttpRequestResponse(stored.getMessage());
			OriginalRequestResponse restored = new OriginalRequestResponse(stored.getId(), message, stored.getMethod(),
					stored.getUrl(), stored.getInfoText(), stored.getStatusCode(), stored.getResponseContentLength());
			restored.restoreViewState(stored.getComment(), stored.isMarked());
			config.getTableModel().addNewRequestResponse(restored);
			if (stored.getId() > maxId) {
				maxId = stored.getId();
			}
		}
		for (Map.Entry<String, ArrayList<Integer>> entry : index.sessions.entrySet()) {
			Session session = config.getSessionByName(entry.getKey());
			if (session == null) {
				BurpExtender.callbacks.printOutput("[AuthAnalyzer][restore-session] session not found: " + entry.getKey());
				continue;
			}
			for (Integer id : entry.getValue()) {
				StoredAnalyzerRequestResponse stored = loadStoredSession(entry.getKey(), id);
				BurpExtender.callbacks.printOutput(String.format(
						"[AuthAnalyzer][restore-session] session=%s id=%d stored=%s message=%s",
						entry.getKey(), id, stored == null ? "null" : "ok", (stored == null || stored.getMessage() == null) ? "null" : "ok"));
				if (stored == null) {
					continue;
				}
				AnalyzerRequestResponse restored = new AnalyzerRequestResponse(toHttpRequestResponse(stored.getMessage()),
						stored.getStatus() == null ? null : BypassConstants.valueOf(stored.getStatus()), stored.getInfoText(),
						stored.getStatusCode(), stored.getResponseContentLength());
				session.putRequestResponse(id, restored);
				if (id > maxId) {
					maxId = id;
				}
			}
		}
		config.setMapId(maxId);
		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				config.getTableModel().fireTableDataChanged();
			}
		});
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][restore] done tableRows=%d maxId=%d",
				config.getTableModel().getRowCount(), maxId));
	}

	public static void deleteStoredRequestResponse(int id) {
		StoredIndex index = loadIndex();
		if (index == null) {
			return;
		}
		index.originalIds.remove(Integer.valueOf(id));
		deletePath(ORIGINAL_BASE_PATH + id);
		for (String sessionName : new ArrayList<String>(index.sessions.keySet())) {
			ArrayList<Integer> ids = index.sessions.get(sessionName);
			ids.remove(Integer.valueOf(id));
			deletePath(getSessionPath(sessionName, id));
			if (ids.isEmpty()) {
				index.sessions.remove(sessionName);
			}
		}
		saveIndex(index);
	}

	public static void clearStoredMessages() {
		StoredIndex index = loadIndex();
		if (index == null) {
			return;
		}
		for (Integer id : new ArrayList<Integer>(index.originalIds)) {
			deletePath(ORIGINAL_BASE_PATH + id);
		}
		for (Map.Entry<String, ArrayList<Integer>> entry : index.sessions.entrySet()) {
			for (Integer id : entry.getValue()) {
				deletePath(getSessionPath(entry.getKey(), id));
			}
		}
		deletePath(INDEX_PATH);
	}

	private static void saveOriginalRequestResponse(StoredOriginalRequestResponse stored) {
		storeJsonMessage(ORIGINAL_BASE_PATH + stored.getId(), GSON.toJson(stored));
		StoredIndex index = loadIndex();
		if (!index.originalIds.contains(stored.getId())) {
			index.originalIds.add(stored.getId());
			Collections.sort(index.originalIds);
		}
		saveIndex(index);
	}

	private static void saveSessionRequestResponse(String sessionName, int id, StoredAnalyzerRequestResponse stored) {
		String path = getSessionPath(sessionName, id);
		String json = GSON.toJson(stored);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-session-persist] session=" + sessionName + " id=" + id
				+ " path=" + path + " jsonLen=" + (json == null ? -1 : json.length()));
		storeJsonMessage(path, json);
		StoredIndex index = loadIndex();
		ArrayList<Integer> ids = index.sessions.get(sessionName);
		if (ids == null) {
			ids = new ArrayList<Integer>();
			index.sessions.put(sessionName, ids);
		}
		if (!ids.contains(id)) {
			ids.add(id);
			Collections.sort(ids);
		}
		saveIndex(index);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-session-persist] session=" + sessionName + " id=" + id
				+ " indexIds=" + ids);
	}

	private static StoredOriginalRequestResponse loadStoredOriginal(int id) {
		return readJsonMessage(ORIGINAL_BASE_PATH + id, StoredOriginalRequestResponse.class);
	}

	private static StoredAnalyzerRequestResponse loadStoredSession(String sessionName, int id) {
		String path = getSessionPath(sessionName, id);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-session] session=" + sessionName + " id=" + id + " path=" + path);
		StoredAnalyzerRequestResponse stored = readJsonMessage(path, StoredAnalyzerRequestResponse.class);
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][load-session] session=%s id=%d stored=%s req=%d resp=%d status=%s info=%s",
				sessionName, id, stored == null ? "null" : "ok",
				stored == null || stored.getMessage() == null || stored.getMessage().getRequest() == null ? -1 : stored.getMessage().getRequest().length,
				stored == null || stored.getMessage() == null || stored.getMessage().getResponse() == null ? -1 : stored.getMessage().getResponse().length,
				stored == null ? null : stored.getStatus(),
				stored == null ? null : stored.getInfoText()));
		return stored;
	}

	private static <T> T readJsonMessage(String path, Class<T> type) {
		IHttpRequestResponse[] messages = BurpExtender.callbacks.getSiteMap(HTTPSERVICE.toString() + path);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][read-json] path=" + path + " entries=" + messages.length);
		if (messages.length == 0) {
			return null;
		}
		for (int i = messages.length - 1; i >= 0; i--) {
			try {
				byte[] response = messages[i].getResponse();
				BurpExtender.callbacks.printOutput("[AuthAnalyzer][read-json] path=" + path + " candidateIndex=" + i + " responseBytes=" + (response == null ? -1 : response.length));
				if (response == null || response.length == 0) {
					continue;
				}
				return GSON.fromJson(new String(response), type);
			} catch (Exception e) {
				BurpExtender.callbacks.printOutput("[AuthAnalyzer][read-json][error] path=" + path + " candidateIndex=" + i + " msg=" + e.getMessage());
			}
		}
		return null;
	}

	private static void storeJsonMessage(String path, String jsonBody) {
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-json] path=" + path + " bodyLen=" + (jsonBody == null ? -1 : jsonBody.length()));
		IHttpRequestResponse message = buildStorageMessage(path, jsonBody == null ? null : jsonBody.getBytes());
		if (message != null) {
			BurpExtender.callbacks.addToSiteMap(message);
			IHttpRequestResponse[] messages = BurpExtender.callbacks.getSiteMap(HTTPSERVICE.toString() + path);
			BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-json] path=" + path + " entriesAfterWrite=" + messages.length);
		}
	}

	private static void deletePath(String path) {
		// Burp Extender API does not expose removeFromSiteMap; overwrite the path with an empty payload instead.
		storeJsonMessage(path, null);
	}

	private static IHttpRequestResponse getSettingsMessage() {
		return buildStorageMessage(SETTINGS_PATH, getSetupAsJsonString().getBytes());
	}

	private static IHttpRequestResponse buildStorageMessage(String path, byte[] responseBytes) {
		URL url = null;
		try {
			url = new URL(HTTPSERVICE.getProtocol(), HTTPSERVICE.getHost(), HTTPSERVICE.getPort(), path);
		} catch (MalformedURLException e) {
			return null;
		}
		byte[] request = BurpExtender.callbacks.getHelpers().buildHttpRequest(url);
		final byte[] finalResponseBytes = responseBytes;
		IHttpRequestResponse message = new IHttpRequestResponse() {

			@Override
			public void setResponse(byte[] message) {
			}

			@Override
			public void setRequest(byte[] message) {
			}

			@Override
			public void setHttpService(IHttpService httpService) {
			}

			@Override
			public void setHighlight(String color) {
			}

			@Override
			public void setComment(String comment) {
			}

			@Override
			public byte[] getResponse() {
				return finalResponseBytes;
			}

			@Override
			public byte[] getRequest() {
				return request;
			}

			@Override
			public IHttpService getHttpService() {
				return HTTPSERVICE;
			}

			@Override
			public String getHighlight() {
				return null;
			}

			@Override
			public String getComment() {
				return null;
			}
		};
		return message;
	}

	private static StoredHttpMessage toStoredHttpMessage(IHttpRequestResponse message) {
		if (message == null || message.getHttpService() == null) {
			return null;
		}
		IHttpService service = message.getHttpService();
		return new StoredHttpMessage(service.getHost(), service.getPort(), "https".equalsIgnoreCase(service.getProtocol()),
				message.getRequest(), message.getResponse());
	}

	private static IHttpRequestResponse toHttpRequestResponse(StoredHttpMessage stored) {
		if (stored == null) {
			return null;
		}
		final IHttpService service = BurpExtender.callbacks.getHelpers().buildHttpService(stored.getHost(), stored.getPort(), stored.isHttps());
		final byte[] request = stored.getRequest();
		final byte[] response = stored.getResponse();
		return new IHttpRequestResponse() {

			@Override
			public void setResponse(byte[] message) {
			}

			@Override
			public void setRequest(byte[] message) {
			}

			@Override
			public void setHttpService(IHttpService httpService) {
			}

			@Override
			public void setHighlight(String color) {
			}

			@Override
			public void setComment(String comment) {
			}

			@Override
			public byte[] getResponse() {
				return response;
			}

			@Override
			public byte[] getRequest() {
				return request;
			}

			@Override
			public IHttpService getHttpService() {
				return service;
			}

			@Override
			public String getHighlight() {
				return null;
			}

			@Override
			public String getComment() {
				return null;
			}
		};
	}

	private static String getSessionPath(String sessionName, int id) {
		return SESSION_BASE_PATH + sanitizePathSegment(sessionName) + "/" + id;
	}

	private static String sanitizePathSegment(String value) {
		return value.replaceAll("[^a-zA-Z0-9._-]", "_");
	}

	private static StoredIndex loadIndex() {
		StoredIndex index = readJsonMessage(INDEX_PATH, StoredIndex.class);
		if (index == null) {
			index = new StoredIndex();
		}
		if (index.originalIds == null) {
			index.originalIds = new ArrayList<Integer>();
		}
		if (index.sessions == null) {
			index.sessions = new HashMap<String, ArrayList<Integer>>();
		}
		return index;
	}

	private static void saveIndex(StoredIndex index) {
		Collections.sort(index.originalIds);
		for (ArrayList<Integer> ids : index.sessions.values()) {
			Collections.sort(ids);
		}
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][save-index] originalCount=%d sessionCount=%d sessions=%s",
				index.originalIds == null ? -1 : index.originalIds.size(),
				index.sessions == null ? -1 : index.sessions.size(),
				index.sessions));
		storeJsonMessage(INDEX_PATH, GSON.toJson(index));
	}

	private static class StoredIndex {
		private ArrayList<Integer> originalIds = new ArrayList<Integer>();
		private Map<String, ArrayList<Integer>> sessions = new HashMap<String, ArrayList<Integer>>();
	}
}
