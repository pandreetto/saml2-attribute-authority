package it.infn.security.saml.datasource;

public class DataSourceFactory {

    private static DataSource dataSource = null;

    public static synchronized DataSource getDataSource()
        throws DataSourceException {

        if (dataSource == null) {
            /*
             * TODO class loading
             */
            dataSource = new it.infn.security.saml.datasource.mongodb.MongoDataSource();

            dataSource.init();
        }

        return dataSource;
    }

}