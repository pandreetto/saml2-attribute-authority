package it.infn.security.saml.datasource;

import java.util.Collection;
import java.util.Date;

public interface Resource {

    public String getResourceId()
        throws DataSourceException;

    public void setResourceId(String id)
        throws DataSourceException;

    public Date getResourceCreationDate()
        throws DataSourceException;

    public void setResourceCreationDate(Date cDate)
        throws DataSourceException;

    public Date getResourceChangeDate()
        throws DataSourceException;

    public void setResourceChangeDate(Date cDate)
        throws DataSourceException;

    public String getResourceVersion()
        throws DataSourceException;

    public void setResourceVersion(String version)
        throws DataSourceException;

    public String getResourceExtId()
        throws DataSourceException;

    public void setResourceExtId(String id)
        throws DataSourceException;

    /*
     * TODO move away
     */
    public Collection<String[]> getSPIDAttributes()
        throws DataSourceException;

}