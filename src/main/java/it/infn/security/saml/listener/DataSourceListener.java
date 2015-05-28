package it.infn.security.saml.listener;

import java.util.logging.Level;
import java.util.logging.Logger;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class DataSourceListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(DataSourceListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

    }

    public void contextDestroyed(ServletContextEvent event) {

        try {

            DataSource dataSource = DataSourceFactory.getDataSource();
            if (dataSource != null) {
                dataSource.close();
            }

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

}