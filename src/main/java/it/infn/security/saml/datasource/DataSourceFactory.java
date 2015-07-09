package it.infn.security.saml.datasource;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

public class DataSourceFactory {

    private static DataSource dataSource = null;

    public static DataSource getDataSource()
        throws DataSourceException {

        if (dataSource == null) {

            synchronized (DataSourceFactory.class) {

                if (dataSource == null) {

                    try {
                        AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

                        Class<?> cls = Class.forName(config.getDataSourceClass());
                        dataSource = (DataSource) cls.newInstance();

                    } catch (Exception ex) {
                        throw new DataSourceException("Cannot load data source", ex);
                    }

                    dataSource.init();

                }

            }

        }

        return dataSource;
    }

}