package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;

import java.util.List;

public class SCIM2Group
    extends SCIM2Resource
    implements GroupResource {

    public void setName(String name)
        throws DataSourceException {

    }

    public String getName()
        throws DataSourceException {
        return null;
    }

    public void setUserMembers(List<String> idLists)
        throws DataSourceException {

    }

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException {

    }

    public List<String> getAllMembers()
        throws DataSourceException {
        return null;
    }

}