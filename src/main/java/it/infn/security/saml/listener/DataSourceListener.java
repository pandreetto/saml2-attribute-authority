package it.infn.security.saml.listener;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class DataSourceListener
    implements ServletContextListener {

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            DataSource dataSource = DataSourceFactory.getDataSource();
            if (dataSource != null) {
                dataSource.close();
            }

        } catch (Throwable th) {
            /*
             * TODO missing log
             */
        }

    }

}