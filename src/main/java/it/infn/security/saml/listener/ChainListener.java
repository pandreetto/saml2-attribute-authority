package it.infn.security.saml.listener;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class ChainListener
    implements ServletContextListener {

    @SuppressWarnings("unchecked")
    public void contextInitialized(ServletContextEvent event) {

        try {

            HashMap<String, String> pTable = new HashMap<String, String>();

            ServletContext ctx = event.getServletContext();
            Enumeration<String> parameters = ctx.getInitParameterNames();
            while (parameters.hasMoreElements()) {
                String tmpp = parameters.nextElement();
                pTable.put(tmpp, ctx.getInitParameter(tmpp));
            }

            /*
             * Configuration and log must be initialized before any other
             * subsystem
             */
            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            config.init(pTable);

            DataSourceListener dsListener = new DataSourceListener();
            dsListener.contextInitialized(event);

        } catch (Throwable th) {
            /*
             * TODO missing log
             */
        }

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            DataSourceListener dsListener = new DataSourceListener();
            dsListener.contextDestroyed(event);

        } catch (Throwable th) {
            /*
             * TODO missing log
             */
        }

    }

}