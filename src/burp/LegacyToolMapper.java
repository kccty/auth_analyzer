package burp;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

public final class LegacyToolMapper {

	private LegacyToolMapper() {}

	public static int toLegacyToolFlag(ToolSource toolSource) {
		if (toolSource == null) {
			return 0;
		}
		ToolType type = toolSource.toolType();
		if (type == null) {
			return 0;
		}
		switch (type) {
			case PROXY:
				return IBurpExtenderCallbacks.TOOL_PROXY;
			case REPEATER:
				return IBurpExtenderCallbacks.TOOL_REPEATER;
			case INTRUDER:
				return IBurpExtenderCallbacks.TOOL_INTRUDER;
			case SCANNER:
				return IBurpExtenderCallbacks.TOOL_SCANNER;
			case SEQUENCER:
				return IBurpExtenderCallbacks.TOOL_SEQUENCER;
			case DECODER:
				return IBurpExtenderCallbacks.TOOL_DECODER;
			case COMPARER:
				return IBurpExtenderCallbacks.TOOL_COMPARER;
			case EXTENSIONS:
				return IBurpExtenderCallbacks.TOOL_EXTENDER;
			case TARGET:
				return IBurpExtenderCallbacks.TOOL_TARGET;
			default:
				return 0;
		}
	}
}
