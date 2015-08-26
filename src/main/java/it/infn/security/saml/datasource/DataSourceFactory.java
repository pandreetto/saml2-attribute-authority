package it.infn.security.saml.datasource;

public class DataSourceFactory {

    private static DataSource dataSource = null;

    public static DataSource getDataSource()
        throws DataSourceException {

        if (dataSource == null) {

            synchronized (DataSourceFactory.class) {

                if (dataSource == null) {

                    try {

                        int maxPriority = -1;
                        for (DataSource tmpds : DataSource.dataSourceLoader) {
                            if (tmpds.getLoadPriority() > maxPriority) {
                                maxPriority = tmpds.getLoadPriority();
                                dataSource = tmpds;
                            }
                        }

                    } catch (Exception ex) {
                        throw new DataSourceException("Cannot load data source", ex);
                    }

                    if (dataSource == null) {
                        throw new DataSourceException("Cannot find data source");
                    }

                    dataSource.init();

                }

            }

        }

        return dataSource;
    }

}