package it.infn.security.scim.core;

import java.util.Collection;
import java.util.Date;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.Resource;
import it.infn.security.saml.schema.AttributeEntry;

public class SCIM2Resource
    implements Resource {

    public String getResourceId()
        throws DataSourceException {
        return null;
    }

    public void setResourceId(String id)
        throws DataSourceException {

    }

    public Date getResourceCreationDate()
        throws DataSourceException {
        return null;
    }

    public void setResourceCreationDate(Date cDate)
        throws DataSourceException {

    }

    public Date getResourceChangeDate()
        throws DataSourceException {
        return null;
    }

    public void setResourceChangeDate(Date cDate)
        throws DataSourceException {

    }

    public String getResourceVersion()
        throws DataSourceException {
        return null;
    }

    public void setResourceVersion(String version)
        throws DataSourceException {

    }

    public String getResourceExtId()
        throws DataSourceException {
        return null;
    }

    public void setResourceExtId(String id)
        throws DataSourceException {

    }

    public Collection<AttributeEntry> getExtendedAttributes()
        throws DataSourceException {
        return null;
    }

    public void setExtendedAttributes(Collection<AttributeEntry> xAttributes)
        throws DataSourceException {

    }

}