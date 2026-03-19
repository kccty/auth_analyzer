package com.protect7.authanalyzer.gui.main;

import java.awt.Component;
import java.util.HashMap;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

public class RequestResponsePanel extends JTabbedPane {
	
	private static final long serialVersionUID = 5940984512441844430L;
	public final String TITLE_ORIGINAL = "Original";
	private final HashMap<String, SessionTabbedPane> sessionTabbedPaneMap = new HashMap<String, SessionTabbedPane>();
	private final CenterPanel centerPanel;
	private final int paneId;
	private int selectedIndex = 0;
	
	public RequestResponsePanel(int paneId, CenterPanel centerPanel) {
		this.paneId = paneId;
		this.centerPanel = centerPanel;
		init();
		addChangeListener(e -> {
			SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
			if(sessionTabbedPane != null && sessionTabbedPane.getTabCount() == 2) {
				if(sessionTabbedPane.getSelectedIndex() != selectedIndex) {
					sessionTabbedPane.setSelectedIndex(selectedIndex);
				}
				else {
					centerPanel.updateDiffPane();
				}
			}
		});
	}

	public void init() {
		removeAll();
		SessionTabbedPane originalSessionTabbedPane = new SessionTabbedPane(TITLE_ORIGINAL);
		add(TITLE_ORIGINAL, originalSessionTabbedPane);
		sessionTabbedPaneMap.put(TITLE_ORIGINAL, originalSessionTabbedPane);
		for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			SessionTabbedPane sessionTabbedPane = new SessionTabbedPane(session.getName());
			add(session.getName(), sessionTabbedPane);
			sessionTabbedPaneMap.put(session.getName(), sessionTabbedPane);
		}
		if(paneId == 1 && getTabCount() > 1) {
			setSelectedIndex(1);
		}
	}
	
	public void setRequestMessage(String sessionName, Component component, HttpRequestEditor messageEditor) {
		if(sessionTabbedPaneMap.containsKey(sessionName)) {
			sessionTabbedPaneMap.get(sessionName).setRequestMessage(component, messageEditor);
		}
	}
	
	public void setResponseMessage(String sessionName, Component component, HttpResponseEditor messageEditor) {
		if(sessionTabbedPaneMap.containsKey(sessionName)) {
			sessionTabbedPaneMap.get(sessionName).setResponseMessage(component, messageEditor);
		}
	}
	
	public String getSelectedSession() {
		return getTitleAt(getSelectedIndex());
	}
	
	public String getSelectedMessage() {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null) {
			return sessionTabbedPane.getTitleAt(sessionTabbedPane.getSelectedIndex());
		}
		return null;
	}
	
	public SessionTabbedPane getSelectedSessionTabbedPane() {
		return (SessionTabbedPane) getSelectedComponent();
	}
	
	public String getCurrentMessageString() {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null) {
			return sessionTabbedPane.getCurrentMessageString();
		}
		return null;
	}
	
	public boolean setTabbedPaneIndex(int index) {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null) {
			if(sessionTabbedPane.getSelectedIndex() != index) {
				if(sessionTabbedPane.getTabCount() > index) {
					sessionTabbedPane.setSelectedIndex(index);
					return true;
				}
			}
		}
		return false;
	}
	
	private class SessionTabbedPane extends JTabbedPane {
		
		private static final long serialVersionUID = -4100725845615986632L;
		private final String TITLE_REQUEST = "Request";
		private final String TITLE_RESPONSE = "Response";
		private HttpRequestEditor requestMessageEditor = null;
		private HttpResponseEditor responseMessageEditor = null;
		private HttpRequest requestMessage = null;
		private HttpResponse responseMessage = null;
		
		public SessionTabbedPane(String name) {
			add(TITLE_REQUEST, new JPanel());
			add(TITLE_RESPONSE, new JPanel());
			addChangeListener(e -> {
				selectedIndex = getSelectedIndex();
				centerPanel.updateOtherTabbedPane(paneId, getSelectedIndex());
			});
		}
		
		public void setRequestMessage(Component component, HttpRequestEditor messageEditor) {
			requestMessageEditor = messageEditor;
			requestMessage = messageEditor == null ? null : messageEditor.getRequest();
			setComponentAt(0, component);
		}
		
		public void setResponseMessage(Component component, HttpResponseEditor messageEditor) {
			responseMessageEditor = messageEditor;
			responseMessage = messageEditor == null ? null : messageEditor.getResponse();
			setComponentAt(1, component);
		}
		
		public String getCurrentMessageString() {
			if(getSelectedIndex() == 0) {
				if(requestMessage != null) {
					return requestMessage.toString();
				}
			}
			if(getSelectedIndex() == 1) {
				if(responseMessage != null) {
					return responseMessage.toString();
				}
			}
			return null;
		}
	}
}