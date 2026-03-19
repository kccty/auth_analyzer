package com.protect7.authanalyzer.filter;

public class StatusCodeFilter extends RequestFilter {
	
	public StatusCodeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"304"});
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if (onOffButton.isSelected() && context.getStatusCode() != null) {
			String statusCode = String.valueOf(context.getStatusCode());
			for (String stringLiteral : stringLiterals) {
				if (statusCode.equals(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}
	
	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}