package com.protect7.authanalyzer.filter;

public class FileTypeFilter extends RequestFilter {
	

	public FileTypeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"js", "script", "css", "png", "jpg", "jpeg", "gif", "svg", "bmp", "woff", "ico"});
	}
	
	@Override
	public boolean filterRequest(RequestFilterContext context) {
		if(onOffButton.isSelected()) {
			String path = context.getPath() == null ? "" : context.getPath().toLowerCase();
			String inferredMimeType = context.getInferredMimeType() == null ? "" : context.getInferredMimeType().toLowerCase();
			for(String fileType : stringLiterals) {
				if(path.endsWith(fileType.toLowerCase()) && !fileType.equals("")) {
					incrementFiltered();
					return true;
				}
				else if(!inferredMimeType.isEmpty() && fileType.toLowerCase().equals(inferredMimeType)) {
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