package com.protect7.authanalyzer.filter;

public class PathFilter extends RequestFilter {

	public PathFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if(onOffButton.isSelected() && context.getPath() != null) {
			String url = context.getPath().toLowerCase();
			for(String stringLiteral : stringLiterals) {
				if(url.contains(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
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
