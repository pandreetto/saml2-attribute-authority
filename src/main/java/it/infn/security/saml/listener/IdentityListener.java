package it.infn.security.saml.listener;

import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class IdentityListener
    implements ServletContextListener {

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            IdentityManager manager = IdentityManagerFactory.getManager();
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