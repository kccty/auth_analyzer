package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;

public class OnlyProxyFilter extends RequestFilter {

	public OnlyProxyFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		int toolFlag = context.getToolFlag();
		if(onOffButton.isSelected()) {
			if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
				return false;
			}
			else if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
				incrementFiltered();
			}
		}
		else {
			//Only allow Repeater beside of Proxy
			if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER || toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}