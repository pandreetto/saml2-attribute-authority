package it.infn.security.saml.listener;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class ChainListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(ChainListener.class.getName());

    private IdentityListener idListener;

    private AccessListener accessListener;

    private DataSourceListener dsListener;

    private SCIMListener scimListener;

    private MetadataSourceListener mdListener;

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
             * Configuration and log must be initialized before any other subsystem
             */
            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            config.init(pTable);

            idListener = new IdentityListener();
            idListener.contextInitialized(event);
            accessListener = new AccessListener();
            accessListener.contextInitialized(event);
            dsListener = new DataSourceListener();
            dsListener.contextInitialized(event);
            scimListener = new SCIMListener();
            scimListener.contextInitialized(event);
            mdListener = new MetadataSourceListener();
            mdListener.contextInitialized(event);

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            mdListener.contextDestroyed(event);
            scimListener.contextDestroyed(event);
            dsListener.contextDestroyed(event);
            accessListener.contextInitialized(event);
            idListener.contextDestroyed(event);

            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            config.close();

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

}