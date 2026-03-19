package com.protect7.authanalyzer.filter;

public class InScopeFilter extends RequestFilter {

	public InScopeFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if (onOffButton.isSelected() && !context.isInScope()) {
			incrementFiltered();
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}