package burp;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JPanel;

public class LegacyMessageEditorAdapter implements IMessageEditor {

	private final JPanel panel = new JPanel();
	private byte[] message;

	public LegacyMessageEditorAdapter(Object api, IMessageEditorController controller, boolean editable) {
		panel.add(new JLabel("Montoya single-entry test editor"));
	}

	@Override
	public Component getComponent() {
		return panel;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;
	}

	@Override
	public byte[] getMessage() {
		return message;
	}

	@Override
	public boolean isMessageModified() {
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		return null;
	}

	@Override
	public int[] getSelectionBounds() {
		return new int[] { 0, 0 };
	}

}
