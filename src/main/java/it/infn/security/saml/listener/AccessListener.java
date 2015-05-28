package it.infn.security.saml.listener;

import java.util.logging.Level;
import java.util.logging.Logger;

import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class AccessListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(AccessListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            AccessManager manager = AccessManagerFactory.getManager();
            if (manager != null) {
                manager.close();
            }

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

}