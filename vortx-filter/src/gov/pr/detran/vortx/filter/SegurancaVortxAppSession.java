package gov.pr.detran.vortx.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface SegurancaVortxAppSession {

	public void add(HttpServletRequest request, HttpServletResponse response);
	
}
