package com.protect7.authanalyzer.filter;

public class QueryFilter extends RequestFilter {

	public QueryFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if(onOffButton.isSelected()) {
			if(context.getQuery() != null) {
				String query = context.getQuery().toLowerCase();
				for(String stringLiteral : stringLiterals) {
					if(query.contains(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
						incrementFiltered();
						return true;
					}
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
