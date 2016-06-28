package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.Resource;
import it.infn.security.saml.schema.AttributeEntry;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

public class SCIM2Resource
    implements Resource {

    protected String id = null;

    protected String extId = null;

    protected Date cDate = null;

    protected Date mDate = null;

    protected String version = null;

    protected Collection<AttributeEntry> attributes;

    public String getResourceId()
        throws DataSourceException {

        if (id == null)
            id = UUID.randomUUID().toString();
        return id;
    }

    public void setResourceId(String id)
        throws DataSourceException {
        if (this.id != null)
            throw new DataSourceException("Cannot change resource id");
        this.id = id;
    }

    public Date getResourceCreationDate()
        throws DataSourceException {
        return cDate;
    }

    public void setResourceCreationDate(Date cDate)
        throws DataSourceException {
        if (this.cDate != null)
            throw new DataSourceException("Cannot change resource creation time");
        this.cDate = cDate;
    }

    public Date getResourceChangeDate()
        throws DataSourceException {
        return mDate;
    }

    public void setResourceChangeDate(Date cDate)
        throws DataSourceException {
        this.mDate = cDate;
    }

    public String getResourceVersion()
        throws DataSourceException {
        return version;
    }

    public void setResourceVersion(String version)
        throws DataSourceException {
        this.version = version;
    }

    public String getResourceExtId()
        throws DataSourceException {
        return extId;
    }

    public void setResourceExtId(String id)
        throws DataSourceException {
        extId = id;
    }

    public Collection<AttributeEntry> getExtendedAttributes()
        throws DataSourceException {
        return attributes;
    }

    public void setExtendedAttributes(Collection<AttributeEntry> xAttributes)
        throws DataSourceException {
        attributes = xAttributes;
    }

}