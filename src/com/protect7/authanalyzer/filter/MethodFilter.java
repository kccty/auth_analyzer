package com.protect7.authanalyzer.filter;

public class MethodFilter extends RequestFilter {
	
	public MethodFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"OPTIONS"});
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if(onOffButton.isSelected()) {
			String requestMethod = context.getMethod() == null ? "" : context.getMethod();
			for(String method : stringLiterals) {
				if(requestMethod.toLowerCase().equals(method.toLowerCase()) && !method.trim().equals("")) {
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