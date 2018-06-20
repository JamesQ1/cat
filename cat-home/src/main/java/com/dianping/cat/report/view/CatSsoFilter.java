package com.dianping.cat.report.view;

import com.dianping.cat.system.page.login.service.*;
import com.onelogin.saml2.Auth;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Created by jamesqq on 2018/6/14.
 */
public class CatSsoFilter implements Filter {

    public FilterConfig config;

    CookieManager cookieManager = new CookieManager();
    TokenBuilder tokenBuilder = new TokenBuilder();
    SessionManager sessionManager = new SessionManager();

    @Override
    public void destroy() {
        this.config = null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest hrequest = (HttpServletRequest)request;
        String logonStrings = config.getInitParameter("logonStrings");
        String[] logonList = logonStrings.split(";");
        if(isContains(hrequest.getRequestURI(), logonList)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        SigninContext sc = new SigninContext(httpServletRequest, httpServletResponse);
        Session session = this.validate(sc);
        if(session == null) {
            HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper((HttpServletResponse) response);
            try {
                Auth auth = new Auth(httpServletRequest, httpServletResponse);
                if(request.getParameter("SAMLResponse") == null) {
                    auth.login();
                    return;
                }
                auth.processResponse();
                Map<String, List<String>> attributes = auth.getAttributes();
                String nameId = null;
                for(Map.Entry<String, List<String>> entry : attributes.entrySet()) {
                    if(entry.getKey().contains("claims/name")) {
                        nameId = entry.getValue() == null ? null : entry.getValue().get(1); //get(0)取nameId,get(1)取中文名
                        break;
                    }
                }
                String account = nameId == null ? "admin" : nameId; //default
                String password = "abcdef"; //default
                Credential credential = new Credential(account, password);
                this.signin(sc, credential);
                chain.doFilter(request, response);
                return;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            chain.doFilter(request, response);
            return;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
    }

    private static boolean isContains(String container, String[] regx) {
        boolean result = false;

        for (int i = 0; i < regx.length; i++) {
            if (container.indexOf(regx[i]) != -1) {
                return true;
            }
        }
        return result;
    }

    private Session validate(SigninContext ctx) {
        Token token = getToken(ctx, Token.TOKEN);

        if (token != null) {
            Session session = sessionManager.validate(token);

            return session;
        } else {
            return null;
        }
    }

    private Token getToken(SigninContext ctx, String name) {
        String value = cookieManager.getCookie(ctx, name);

        if (value != null) {
            return tokenBuilder.parse(ctx, value);
        } else {
            return null;
        }
    }

    private Session signin(SigninContext ctx, Credential credential) {
        Token token = sessionManager.authenticate(credential);

        if (token != null) {
            Session session = sessionManager.validate(token);
            if (session != null) {
                this.setToken(ctx, token);
            }
            return session;
        } else {
            return null;
        }
    }

    private void setToken(SigninContext ctx, Token token) {
        String name = token.getName();
        String value = tokenBuilder.build(ctx, token);

        cookieManager.setCookie(ctx, name, value);
    }


}
