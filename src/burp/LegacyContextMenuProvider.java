package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

final class LegacyContextMenuProvider implements ContextMenuItemsProvider {

	private final IContextMenuFactory factory;

	LegacyContextMenuProvider(IContextMenuFactory factory) {
		this.factory = factory;
	}

	@Override
	public List<Component> provideMenuItems(ContextMenuEvent event) {
		IContextMenuInvocation invocation = new LegacyContextMenuInvocation(event);
		List<javax.swing.JMenuItem> items = factory.createMenuItems(invocation);
		if (items == null || items.isEmpty()) {
			return null;
		}
		return new ArrayList<Component>(items);
	}

	private static final class LegacyContextMenuInvocation implements IContextMenuInvocation {
		private final ContextMenuEvent event;
		private final IHttpRequestResponse[] selectedMessages;
		private final int[] selectionBounds;
		private final int invocationContext;

		LegacyContextMenuInvocation(ContextMenuEvent event) {
			this.event = event;
			this.selectedMessages = adaptMessages(event);
			this.selectionBounds = adaptSelectionBounds(event.messageEditorRequestResponse());
			this.invocationContext = adaptInvocationContext(event);
		}

		@Override
		public int getToolFlag() {
			return LegacyToolMapper.toLegacyToolFlag(event);
		}

		@Override
		public IHttpRequestResponse[] getSelectedMessages() {
			return selectedMessages;
		}

		@Override
		public int[] getSelectionBounds() {
			return selectionBounds;
		}

		@Override
		public byte getInvocationContext() {
			return (byte) invocationContext;
		}

		@Override
		public java.awt.event.InputEvent getInputEvent() {
			return null;
		}

		@Override
		public IScanIssue[] getSelectedIssues() {
			return new IScanIssue[0];
		}

		private static IHttpRequestResponse[] adaptMessages(ContextMenuEvent event) {
			List<HttpRequestResponse> items = event.selectedRequestResponses();
			if (items == null || items.isEmpty()) {
				Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
				if (editor.isPresent()) {
					return new IHttpRequestResponse[] { new MontoyaHttpRequestResponseAdapter(editor.get().requestResponse()) };
				}
				return new IHttpRequestResponse[0];
			}
			IHttpRequestResponse[] adapted = new IHttpRequestResponse[items.size()];
			for (int i = 0; i < items.size(); i++) {
				adapted[i] = new MontoyaHttpRequestResponseAdapter(items.get(i));
			}
			return adapted;
		}

		private static int[] adaptSelectionBounds(Optional<MessageEditorHttpRequestResponse> messageEditor) {
			if (!messageEditor.isPresent()) {
				return null;
			}
			Optional<Range> offsets = messageEditor.get().selectionOffsets();
			if (!offsets.isPresent()) {
				return null;
			}
			Range range = offsets.get();
			return new int[] { range.startIndexInclusive(), range.endIndexExclusive() };
		}

		private static int adaptInvocationContext(ContextMenuEvent event) {
			Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
			if (!editor.isPresent()) {
				return IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE;
			}
			MessageEditorHttpRequestResponse mer = editor.get();
			boolean request = mer.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
			InvocationType type = event.invocationType();
			if (request) {
				return type == InvocationType.MESSAGE_EDITOR_REQUEST || type == InvocationType.MESSAGE_EDITOR_RESPONSE
					? IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
					: IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST;
			}
			return type == InvocationType.MESSAGE_EDITOR_RESPONSE || type == InvocationType.MESSAGE_EDITOR_REQUEST
				? IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
				: IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE;
		}
	}
}
