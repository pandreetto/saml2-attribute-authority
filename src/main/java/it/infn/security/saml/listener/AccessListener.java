package it.infn.security.saml.listener;

import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class AccessListener
    implements ServletContextListener {

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            AccessManager manager = AccessManagerFactory.getManager();
            if (manager != null) {
                manager.close();
            }

        } catch (Throwable th) {
            /*
             * TODO missing log
             */
        }

    }

}