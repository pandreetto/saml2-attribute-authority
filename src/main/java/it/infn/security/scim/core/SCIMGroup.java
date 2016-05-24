package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;

import java.util.Date;
import java.util.List;

import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.objects.Group;

public class SCIMGroup
    extends Group
    implements GroupResource {

    public static final long serialVersionUID = 1463734695;

    public SCIMGroup() {
        super();
    }

    public String getResourceId()
        throws DataSourceException {
        try {
            return super.getId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceId(String id)
        throws DataSourceException {
        try {
            super.setId(id);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public Date getResourceCreationDate()
        throws DataSourceException {
        try {
            return super.getCreatedDate();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceCreationDate(Date cDate)
        throws DataSourceException {
        try {
            super.setCreatedDate(cDate);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public Date getResourceChangeDate()
        throws DataSourceException {
        try {
            return super.getLastModified();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }

    }

    public void setResourceChangeDate(Date cDate)
        throws DataSourceException {
        try {
            super.setLastModified(cDate);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getResourceVersion()
        throws DataSourceException {
        try {
            return super.getVersion();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceVersion(String version)
        throws DataSourceException {
        try {
            super.setVersion(version);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getResourceExtId()
        throws DataSourceException {
        try {
            return super.getExternalId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceExtId(String id)
        throws DataSourceException {
        try {
            if (id != null)
                super.setExternalId(id);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setName(String name)
        throws DataSourceException {
        try {
            super.setDisplayName(name);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getName()
        throws DataSourceException {
        try {
            return super.getDisplayName();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserMembers(List<String> idLists)
        throws DataSourceException {
        try {
            for (String id : idLists) {
                super.setUserMember(id);
            }
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException {
        try {
            for (String id : idLists) {
                super.setGroupMember(id);
            }
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<String> getAllMembers()
        throws DataSourceException {
        try {
            return super.getMembers();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

}