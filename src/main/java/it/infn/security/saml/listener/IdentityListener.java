package it.infn.security.saml.listener;

import java.util.logging.Level;
import java.util.logging.Logger;

import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class IdentityListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(IdentityListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            IdentityManager manager = IdentityManagerFactory.getManager();
            if (manager != null) {
                manager.close();
            }

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

}