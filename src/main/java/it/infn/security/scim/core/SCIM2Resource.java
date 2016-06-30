package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.Resource;
import it.infn.security.saml.schema.AttributeEntry;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

public abstract class SCIM2Resource
    implements Resource {

    private String id;

    private String extId;

    private Date cDate;

    private Date mDate;

    private String version;

    private Collection<AttributeEntry> attributes;

    private Date initDate;

    public SCIM2Resource() {
        id = null;
        extId = null;
        cDate = null;
        mDate = null;
        version = null;

        initDate = new Date();
    }

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
        if (cDate == null) {
            cDate = initDate;
        }
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
        if (mDate == null) {
            mDate = getResourceCreationDate();
        }
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
        if (this.version != null) {
            resourceUpdated();
        }
        this.version = version;
    }

    public String getResourceExtId()
        throws DataSourceException {
        return extId;
    }

    public void setResourceExtId(String id)
        throws DataSourceException {
        if (extId != null) {
            resourceUpdated();
        }
        extId = id;
    }

    public Collection<AttributeEntry> getExtendedAttributes()
        throws DataSourceException {
        return attributes;
    }

    public void setExtendedAttributes(Collection<AttributeEntry> xAttributes)
        throws DataSourceException {
        if (attributes != null) {
            resourceUpdated();
        }
        attributes = xAttributes;
    }

    protected void resourceUpdated() {
        mDate = new Date();
    }

}