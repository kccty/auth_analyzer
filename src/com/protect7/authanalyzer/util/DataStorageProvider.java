package com.protect7.authanalyzer.util;

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

	private static final String ROOT_KEY = "authanalyzer";
	private static final String SETTINGS_KEY = "settings";
	private static final String INDEX_KEY = "index";
	private static final String ORIGINALS_KEY = "originals";
	private static final String SESSIONS_KEY = "sessions";
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
		String json = getSetupAsJsonString();
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][save-setup] Persisting session/filter setup to ProjectData");
		JsonObject root = rootStorage();
		root.addProperty(SETTINGS_KEY, json);
		saveRootStorage(root);
	}

	public static String loadSetup() {
		JsonObject root = rootStorage();
		String value = root.has(SETTINGS_KEY) && !root.get(SETTINGS_KEY).isJsonNull() ? root.get(SETTINGS_KEY).getAsString() : null;
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-setup] found=" + (value != null));
		return value;
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
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][store-session] session=%s id=%d status=%s req=%d resp=%d info=%s",
				sessionName, id, stored.getStatus(),
				stored.getMessage() == null || stored.getMessage().getRequest() == null ? -1 : stored.getMessage().getRequest().length,
				stored.getMessage() == null || stored.getMessage().getResponse() == null ? -1 : stored.getMessage().getResponse().length,
				stored.getInfoText()));
		saveSessionRequestResponse(sessionName, id, stored);
	}
	
	public static void saveAllStoredMessages() {
		CurrentConfig config = CurrentConfig.getCurrentConfig();
		StoredIndex snapshot = new StoredIndex();
		JsonObject root = rootStorage();
		JsonObject originals = ensureChild(root, ORIGINALS_KEY);
		JsonObject sessions = ensureChild(root, SESSIONS_KEY);
		clearChildObject(originals);
		clearChildObject(sessions);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][save-all] start originals="
				+ config.getTableModel().getOriginalRequestResponseList().size() + " sessions=" + config.getSessions().size());
		for (OriginalRequestResponse requestResponse : config.getTableModel().getOriginalRequestResponseList()) {
			if (requestResponse == null) {
				continue;
			}
			StoredOriginalRequestResponse stored = new StoredOriginalRequestResponse(requestResponse.getId(),
					toStoredHttpMessage(requestResponse.getRequestResponse()), requestResponse.getMethod(), requestResponse.getUrl(),
					requestResponse.getInfoText(), requestResponse.getComment(), requestResponse.getStatusCode(),
					requestResponse.getResponseContentLength(), requestResponse.isMarked());
			storeJsonObject(originals, String.valueOf(stored.getId()), GSON.toJson(stored));
			if (!snapshot.originalIds.contains(stored.getId())) {
				snapshot.originalIds.add(stored.getId());
			}
		}
		Collections.sort(snapshot.originalIds);
		for (Session session : config.getSessions()) {
			ArrayList<Integer> ids = snapshot.sessions.computeIfAbsent(session.getName(), k -> new ArrayList<Integer>());
			JsonObject sessionObject = ensureChild(sessions, sanitizePathSegment(session.getName()));
			for (Map.Entry<Integer, AnalyzerRequestResponse> entry : session.getRequestResponseMap().entrySet()) {
				if (entry.getValue() == null) {
					continue;
				}
				if (!snapshot.originalIds.contains(entry.getKey())) {
					BurpExtender.callbacks.printOutput("[AuthAnalyzer][save-all] skip orphan session entry session="
							+ session.getName() + " id=" + entry.getKey());
					continue;
				}
				StoredAnalyzerRequestResponse stored = new StoredAnalyzerRequestResponse(
						toStoredHttpMessage(entry.getValue().getRequestResponse()),
						entry.getValue().getStatus() == null ? null : entry.getValue().getStatus().name(),
						entry.getValue().getInfoText(), entry.getValue().getStatusCode(),
						entry.getValue().getResponseContentLength());
				storeJsonObject(sessionObject, String.valueOf(entry.getKey()), GSON.toJson(stored));
				if (!ids.contains(entry.getKey())) {
					ids.add(entry.getKey());
				}
			}
			Collections.sort(ids);
		}
		saveRootStorage(root);
		saveIndex(snapshot);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][save-all] done originalIds=" + snapshot.originalIds
				+ " sessionNames=" + snapshot.sessions.keySet());
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
				if (!originalIds.contains(id)) {
					BurpExtender.callbacks.printOutput("[AuthAnalyzer][restore-session] skip orphan session entry session="
							+ entry.getKey() + " id=" + id + " because original id is not present in index.originalIds");
					continue;
				}
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
		JsonObject root = rootStorage();
		JsonObject originals = ensureChild(root, ORIGINALS_KEY);
		JsonObject sessions = ensureChild(root, SESSIONS_KEY);
		originals.remove(String.valueOf(id));
		StoredIndex index = loadIndex();
		if (index == null) {
			return;
		}
		index.originalIds.remove(Integer.valueOf(id));
		for (String sessionName : new ArrayList<String>(index.sessions.keySet())) {
			ArrayList<Integer> ids = index.sessions.get(sessionName);
			ids.remove(Integer.valueOf(id));
			JsonObject sessionObject = getChildObject(sessions, sanitizePathSegment(sessionName));
			if (sessionObject != null) {
				sessionObject.remove(String.valueOf(id));
			}
			if (ids.isEmpty()) {
				index.sessions.remove(sessionName);
				sessions.remove(sanitizePathSegment(sessionName));
			}
		}
		saveRootStorage(root);
		saveIndex(index);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][delete-stored] id=" + id + " updatedIndex originalIds="
				+ index.originalIds + " sessionNames=" + index.sessions.keySet());
	}

	public static void clearStoredMessages() {
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][clear-stored] clearing ProjectData originals/sessions/index");
		JsonObject root = rootStorage();
		root.remove(ORIGINALS_KEY);
		root.remove(SESSIONS_KEY);
		root.remove(INDEX_KEY);
		saveRootStorage(root);
	}

	private static void saveOriginalRequestResponse(StoredOriginalRequestResponse stored) {
		JsonObject root = rootStorage();
		JsonObject originals = ensureChild(root, ORIGINALS_KEY);
		storeJsonObject(originals, String.valueOf(stored.getId()), GSON.toJson(stored));
		saveRootStorage(root);
		StoredIndex index = loadIndex();
		if (!index.originalIds.contains(stored.getId())) {
			index.originalIds.add(stored.getId());
			Collections.sort(index.originalIds);
		}
		saveIndex(index);
	}

	private static void saveSessionRequestResponse(String sessionName, int id, StoredAnalyzerRequestResponse stored) {
		String key = String.valueOf(id);
		String json = GSON.toJson(stored);
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-session-persist] session=" + sessionName + " id=" + id
				+ " jsonLen=" + (json == null ? -1 : json.length()));
		JsonObject root = rootStorage();
		JsonObject sessions = ensureChild(root, SESSIONS_KEY);
		JsonObject sessionObject = ensureChild(sessions, sanitizePathSegment(sessionName));
		storeJsonObject(sessionObject, key, json);
		saveRootStorage(root);
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
		JsonObject originals = ensureChild(rootStorage(), ORIGINALS_KEY);
		return readJsonObject(originals, String.valueOf(id), StoredOriginalRequestResponse.class);
	}

	private static StoredAnalyzerRequestResponse loadStoredSession(String sessionName, int id) {
		JsonObject sessions = ensureChild(rootStorage(), SESSIONS_KEY);
		JsonObject sessionObject = getChildObject(sessions, sanitizePathSegment(sessionName));
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][load-session] session=" + sessionName + " id=" + id);
		StoredAnalyzerRequestResponse stored = readJsonObject(sessionObject, String.valueOf(id), StoredAnalyzerRequestResponse.class);
		BurpExtender.callbacks.printOutput(String.format(
				"[AuthAnalyzer][load-session] session=%s id=%d stored=%s req=%d resp=%d status=%s info=%s",
				sessionName, id, stored == null ? "null" : "ok",
				stored == null || stored.getMessage() == null || stored.getMessage().getRequest() == null ? -1 : stored.getMessage().getRequest().length,
				stored == null || stored.getMessage() == null || stored.getMessage().getResponse() == null ? -1 : stored.getMessage().getResponse().length,
				stored == null ? null : stored.getStatus(),
				stored == null ? null : stored.getInfoText()));
		return stored;
	}

	private static <T> T readJsonObject(JsonObject parent, String key, Class<T> type) {
		if (parent == null) {
			return null;
		}
		try {
			String json = parent.has(key) && !parent.get(key).isJsonNull() ? parent.get(key).getAsString() : null;
			BurpExtender.callbacks.printOutput("[AuthAnalyzer][read-json] key=" + key + " exists=" + (json != null)
					+ " bodyLen=" + (json == null ? -1 : json.length()));
			if (json == null || json.isEmpty()) {
				return null;
			}
			return GSON.fromJson(json, type);
		} catch (Exception e) {
			BurpExtender.callbacks.printOutput("[AuthAnalyzer][read-json][error] key=" + key + " msg=" + e.getMessage());
			return null;
		}
	}

	private static void storeJsonObject(JsonObject parent, String key, String jsonBody) {
		if (parent == null) {
			return;
		}
		BurpExtender.callbacks.printOutput("[AuthAnalyzer][store-json] key=" + key + " bodyLen=" + (jsonBody == null ? -1 : jsonBody.length()));
		if (jsonBody == null) {
			parent.remove(key);
		} else {
			parent.addProperty(key, jsonBody);
		}
	}

	private static JsonObject rootStorage() {
		String json = BurpExtender.callbacks.loadExtensionSetting(ROOT_KEY);
		if (json == null || json.trim().isEmpty()) {
			return new JsonObject();
		}
		try {
			return JsonParser.parseString(json).getAsJsonObject();
		} catch (Exception e) {
			BurpExtender.callbacks.printOutput("[AuthAnalyzer][root-storage][error] failed to parse settings JSON: " + e.getMessage());
			return new JsonObject();
		}
	}

	private static void saveRootStorage(JsonObject root) {
		BurpExtender.callbacks.saveExtensionSetting(ROOT_KEY, root == null ? null : root.toString());
	}

	private static JsonObject ensureChild(JsonObject parent, String key) {
		JsonObject child = getChildObject(parent, key);
		if (child == null) {
			child = new JsonObject();
			parent.add(key, child);
		}
		return child;
	}

	private static JsonObject getChildObject(JsonObject parent, String key) {
		if (parent == null || !parent.has(key) || !parent.get(key).isJsonObject()) {
			return null;
		}
		return parent.getAsJsonObject(key);
	}

	private static void clearChildObject(JsonObject parent) {
		for (String key : new ArrayList<String>(parent.keySet())) {
			parent.remove(key);
		}
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


	private static String sanitizePathSegment(String value) {
		return value.replaceAll("[^a-zA-Z0-9._-]", "_");
	}

	private static StoredIndex loadIndex() {
		JsonObject root = rootStorage();
		String json = root.has(INDEX_KEY) && !root.get(INDEX_KEY).isJsonNull() ? root.get(INDEX_KEY).getAsString() : null;
		StoredIndex index = json == null ? null : GSON.fromJson(json, StoredIndex.class);
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
		JsonObject root = rootStorage();
		root.addProperty(INDEX_KEY, GSON.toJson(index));
		saveRootStorage(root);
	}

	private static class StoredIndex {
		private ArrayList<Integer> originalIds = new ArrayList<Integer>();
		private Map<String, ArrayList<Integer>> sessions = new HashMap<String, ArrayList<Integer>>();
	}
}
