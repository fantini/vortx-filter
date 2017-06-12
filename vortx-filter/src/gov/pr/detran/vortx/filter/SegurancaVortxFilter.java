package gov.pr.detran.vortx.filter;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import br.gov.pr.celepar.ws.rest.security.provider.jdbc.JDBCSecurity;
import br.gov.pr.celepar.ws.rest.security.utils.UtilsHMAC;
import gov.pr.celepar.sentinela.commons.Constants;
import gov.pr.celepar.sentinela.commons.Login;
import gov.pr.celepar.sentinela.commons.pojo.UsuarioAutenticado;
import gov.pr.celepar.sentinela.commons.util.Criptografia;
import gov.pr.celepar.sentinela.commons.util.SentinelaConfig;
import gov.pr.celepar.sentinela.core.client.SistemaHospedeiro;
import gov.pr.celepar.sentinela.core.facade.AutorizacaoFacade;
import gov.pr.celepar.sentinela.persistence.dao.DAOFactory;

public final class SegurancaVortxFilter implements Filter {

	private final SentinelaConfig sentinelaConfig = SentinelaConfig.getInstance();
	private static final Logger logger = Logger.getLogger(SegurancaVortxFilter.class);
	private FilterConfig filterConfig = null;
	public final static String SESSION_ATTRIBUTE = "SESSION_VORTX_LOGIN";
	    
	public SegurancaVortxFilter() {
		super();
	}

	public void init(FilterConfig config) throws ServletException {
		this.filterConfig = config;
		this.sentinelaConfig.loadValues(config.getServletContext());
	}

	public void destroy() {
			logger.info("SentinelaVortxFilter destroy....");
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		HttpServletRequest servletRequest = (HttpServletRequest) request; 
		HttpServletResponse servletResponse = (HttpServletResponse) response;
								
		Login login = (Login) servletRequest.getSession().getAttribute(Constants.SESSION_SENTINELA_LOGIN);
					
		try {
		
			String authorization = isNotBlank(servletRequest.getHeader("Authorization")) ? servletRequest.getHeader("Authorization") : servletRequest.getParameter("Authorization");
			String xdate = isNotBlank(servletRequest.getHeader("X-Date")) ? servletRequest.getHeader("X-Date") : servletRequest.getParameter("X-Date");
			String xuser = isNotBlank(servletRequest.getHeader("X-User")) ? servletRequest.getHeader("X-User") : servletRequest.getParameter("X-User");
			String xurl = isNotBlank(servletRequest.getHeader("X-Url")) ? servletRequest.getHeader("X-Url") : servletRequest.getParameter("X-Url");
			String id = authorization.split(":")[0];
			String signature = authorization.split(":")[1];			
			
			String description = id+xuser+xdate+xurl;
			
			Method method = UtilsHMAC.class.getDeclaredMethod("generateSignature", String.class, String.class);
			method.setAccessible(true);			
			String _signature = (String)method.invoke(null, description, new JDBCSecurity().getSecretKey(id));
			
			Boolean acessoNegado = false;
			
			if (!signature.equals(_signature)) {
				acessoNegado = true;
				logger.error("Error signature "+signature+" : "+_signature);
			}
			
			if (!((new Date()).getTime() - new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(xdate).getTime() < 120000)) {
				acessoNegado = true;
				logger.error("Error date "+xdate+": "+((new Date()).getTime() - new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(xdate).getTime()));
			}
			
			if (acessoNegado)
				throw new Exception("Acesso negado");
			
			if (login == null || !login.isLogado() || !Long.valueOf(login.getUsuario().getCpf()).equals(Long.valueOf(xuser))) {
				
				if (SistemaHospedeiro.getInstance() == null) {
					method = SistemaHospedeiro.class.getDeclaredMethod("getInstance", HttpServletRequest.class);
				    method.setAccessible(true);
				    method.invoke(null, servletRequest);
				}
								
				UsuarioAutenticado usuario = new UsuarioAutenticado(
					DAOFactory.getDAOFactory(SentinelaConfig.getInstance().getDAOFactory()).getUsuarioDAO().obterUsuarioPorCPF(xuser));
								
				AutorizacaoFacade.carregarDefinicoesUsuarioSistema(usuario, SistemaHospedeiro.getInstance().getSistema());
				
				login = new Login();
				
				login.setChave(usuario.getLogin());
				login.setLogado(true);
				login.setUsuario(usuario);
				
				if (SentinelaConfig.getInstance().isEnableEncript()) {
					Criptografia criptografia = new Criptografia();
					String code = criptografia.generateSecurityCode();
					servletRequest.getSession().setAttribute(Constants.SENTINELA_SECURITY_CODE, code);
				}
				
				servletRequest.getSession().setAttribute(Constants.SESSION_SENTINELA_LOGIN, login);
	        	
	        	Cookie cookieU = new Cookie(Constants.SENTINELA_COOKIE_LOGIN, (String)login.getChave());
	    		cookieU.setMaxAge(1296000);
	    		servletResponse.addCookie(cookieU);
				
			}
			
			//App Config - init

			servletRequest.getSession().setAttribute(SESSION_ATTRIBUTE, true);
			
			logger.info("SentinelaVortxFilter init app config....");
			
			String app = filterConfig.getInitParameter("app.config.session");
			
			if (app != null && !app.trim().isEmpty())
				((SegurancaVortxAppSession)Class.forName(app).newInstance()).add(servletRequest, servletResponse);
			
			logger.info("SentinelaVortxFilter end app config....");
			
			//App Config - end		
			
        	servletResponse.sendRedirect(URLDecoder.decode(xurl, "UTF-8"));
        	
        	return;
        	
		} catch (IOException i) {
			throw i;
		} catch (ServletException s) {
			throw s;
		} catch (Exception e) {
			logger.error(e.getMessage(), e.getCause());
		}
		
		chain.doFilter(request, response);
		
	}
	
	private static Boolean isNotBlank(String value) {
		return !(value == null || value.trim().isEmpty());
	}
}
