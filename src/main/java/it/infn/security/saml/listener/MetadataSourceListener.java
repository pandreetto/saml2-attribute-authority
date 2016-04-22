package it.infn.security.saml.listener;

import it.infn.security.saml.spmetadata.MetadataSource;
import it.infn.security.saml.spmetadata.MetadataSourceFactory;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class MetadataSourceListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(MetadataSourceListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            MetadataSource mdSource = MetadataSourceFactory.getMetadataSource();
            if (mdSource != null) {
                mdSource.close();
            }

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

}