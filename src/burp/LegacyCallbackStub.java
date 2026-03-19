package burp;

import java.awt.Component;
import java.io.OutputStream;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import burp.api.montoya.MontoyaApi;

public class LegacyCallbackStub implements IBurpExtenderCallbacks {

	private final MontoyaApi api;
	private final IExtensionHelpers helpers;

	public LegacyCallbackStub() {
		this.api = BurpExtender.montoyaApi;
		this.helpers = new LegacyHelpersAdapter();
	}

	@Override
	public void setExtensionName(String name) { api.extension().setName(name); }
	@Override
	public IExtensionHelpers getHelpers() { return helpers; }
	@Override
	public OutputStream getStdout() { return api.logging().output(); }
	@Override
	public OutputStream getStderr() { return api.logging().error(); }
	@Override
	public void printOutput(String message) { api.logging().logToOutput(message); }
	@Override
	public void printError(String error) { api.logging().logToError(error); }
	@Override
	public void registerContextMenuFactory(IContextMenuFactory factory) {
		api.logging().logToOutput("[AuthAnalyzer][startup] registerContextMenuFactory is a no-op in Montoya single-entry mode");
	}
	@Override
	public IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable) { return new LegacyMessageEditorAdapter(api, controller, editable); }
	@Override
	public String[] getCommandLineArguments() { return new String[0]; }
	@Override
	public void saveExtensionSetting(String name, String value) {
		if (value == null) api.persistence().preferences().deleteString(name);
		else api.persistence().preferences().setString(name, value);
	}
	@Override
	public String loadExtensionSetting(String name) { return api.persistence().preferences().getString(name); }
	@Override
	public void customizeUiComponent(Component component) { api.userInterface().applyThemeToComponent(component); }
	@Override
	public void issueAlert(String message) { api.logging().raiseInfoEvent(message); }
	@Override
	public void unloadExtension() { api.extension().unload(); }

	private UnsupportedOperationException unsupported() { return new UnsupportedOperationException("Not implemented in Montoya single-entry test mode"); }

	@Override public void registerExtensionStateListener(IExtensionStateListener listener) { throw unsupported(); }
	@Override public List<IExtensionStateListener> getExtensionStateListeners() { return Collections.emptyList(); }
	@Override public void removeExtensionStateListener(IExtensionStateListener listener) { throw unsupported(); }
	@Override public void registerHttpListener(IHttpListener listener) { throw unsupported(); }
	@Override public List<IHttpListener> getHttpListeners() { return Collections.emptyList(); }
	@Override public void removeHttpListener(IHttpListener listener) { throw unsupported(); }
	@Override public void registerProxyListener(IProxyListener listener) { throw unsupported(); }
	@Override public List<IProxyListener> getProxyListeners() { return Collections.emptyList(); }
	@Override public void removeProxyListener(IProxyListener listener) { throw unsupported(); }
	@Override public void registerScannerListener(IScannerListener listener) { throw unsupported(); }
	@Override public List<IScannerListener> getScannerListeners() { return Collections.emptyList(); }
	@Override public void removeScannerListener(IScannerListener listener) { throw unsupported(); }
	@Override public void registerScopeChangeListener(IScopeChangeListener listener) { throw unsupported(); }
	@Override public List<IScopeChangeListener> getScopeChangeListeners() { return Collections.emptyList(); }
	@Override public void removeScopeChangeListener(IScopeChangeListener listener) { throw unsupported(); }
	@Override public List<IContextMenuFactory> getContextMenuFactories() { return Collections.emptyList(); }
	@Override public void removeContextMenuFactory(IContextMenuFactory factory) { throw unsupported(); }
	@Override public void registerMessageEditorTabFactory(IMessageEditorTabFactory factory) { throw unsupported(); }
	@Override public List<IMessageEditorTabFactory> getMessageEditorTabFactories() { return Collections.emptyList(); }
	@Override public void removeMessageEditorTabFactory(IMessageEditorTabFactory factory) { throw unsupported(); }
	@Override public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider provider) { throw unsupported(); }
	@Override public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() { return Collections.emptyList(); }
	@Override public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider) { throw unsupported(); }
	@Override public void registerScannerCheck(IScannerCheck check) { throw unsupported(); }
	@Override public List<IScannerCheck> getScannerChecks() { return Collections.emptyList(); }
	@Override public void removeScannerCheck(IScannerCheck check) { throw unsupported(); }
	@Override public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) { throw unsupported(); }
	@Override public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() { return Collections.emptyList(); }
	@Override public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) { throw unsupported(); }
	@Override public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor processor) { throw unsupported(); }
	@Override public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() { return Collections.emptyList(); }
	@Override public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor) { throw unsupported(); }
	@Override public void registerSessionHandlingAction(ISessionHandlingAction action) { throw unsupported(); }
	@Override public List<ISessionHandlingAction> getSessionHandlingActions() { return Collections.emptyList(); }
	@Override public void removeSessionHandlingAction(ISessionHandlingAction action) { throw unsupported(); }
	@Override public void addSuiteTab(ITab tab) { throw unsupported(); }
	@Override public void removeSuiteTab(ITab tab) { throw unsupported(); }
	@Override public ITextEditor createTextEditor() { throw unsupported(); }
	@Override public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) { throw unsupported(); }
	@Override public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) { throw unsupported(); }
	@Override public void sendToIntruder(String host, int port, boolean useHttps, byte[] request, List<int[]> payloadPositionOffsets) { throw unsupported(); }
	@Override public void sendToComparer(byte[] data) { throw unsupported(); }
	@Override public void sendToSpider(URL url) { throw unsupported(); }
	@Override public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request) { throw unsupported(); }
	@Override public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request, List<int[]> insertionPointOffsets) { throw unsupported(); }
	@Override public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) { throw unsupported(); }
	@Override public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) { throw unsupported(); }
	@Override public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request, boolean forceHttp1) { throw unsupported(); }
	@Override public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request) { throw unsupported(); }
	@Override public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request, boolean forceHttp1) { throw unsupported(); }
	@Override public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body) { throw unsupported(); }
	@Override public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body, boolean forceHttp2) { throw unsupported(); }
	@Override public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body, boolean forceHttp2, String connectionIdentifier) { throw unsupported(); }
	@Override public boolean isInScope(URL url) { throw unsupported(); }
	@Override public void includeInScope(URL url) { throw unsupported(); }
	@Override public void excludeFromScope(URL url) { throw unsupported(); }
	@Override public IHttpRequestResponse[] getProxyHistory() { throw unsupported(); }
	@Override public IHttpRequestResponse[] getSiteMap(String urlPrefix) { throw unsupported(); }
	@Override public IScanIssue[] getScanIssues(String urlPrefix) { throw unsupported(); }
	@Override public void generateScanReport(String format, IScanIssue[] issues, java.io.File file) { throw unsupported(); }
	@Override public List<ICookie> getCookieJarContents() { return Collections.emptyList(); }
	@Override public void updateCookieJar(ICookie cookie) { throw unsupported(); }
	@Override public void addToSiteMap(IHttpRequestResponse item) { throw unsupported(); }
	@Override public void restoreState(java.io.File file) { throw unsupported(); }
	@Override public void saveState(java.io.File file) { throw unsupported(); }
	@Override public Map<String, String> saveConfig() { throw unsupported(); }
	@Override public void loadConfig(Map<String, String> config) { throw unsupported(); }
	@Override public String saveConfigAsJson(String... paths) { throw unsupported(); }
	@Override public void loadConfigFromJson(String config) { throw unsupported(); }
	@Override public void setProxyInterceptionEnabled(boolean enabled) { throw unsupported(); }
	@Override public String[] getBurpVersion() { throw unsupported(); }
	@Override public String getExtensionFilename() { throw unsupported(); }
	@Override public boolean isExtensionBapp() { return false; }
	@Override public void exitSuite(boolean promptUser) { throw unsupported(); }
	@Override public ITempFile saveToTempFile(byte[] buffer) { throw unsupported(); }
	@Override public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) { throw unsupported(); }
	@Override public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse httpRequestResponse, List<int[]> requestMarkers, List<int[]> responseMarkers) { throw unsupported(); }
	@Override public String getToolName(int toolFlag) { throw unsupported(); }
	@Override public void addScanIssue(IScanIssue issue) { throw unsupported(); }
	@Override public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() { throw unsupported(); }
	@Override public String[][] getParameters(byte[] request) { throw unsupported(); }
	@Override public String[] getHeaders(byte[] request) { throw unsupported(); }
	@Override public void registerMenuItem(String caption, IMenuItemHandler handler) { throw unsupported(); }
}
