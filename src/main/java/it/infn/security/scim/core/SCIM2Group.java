package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;

import java.util.ArrayList;
import java.util.List;

public class SCIM2Group
    extends SCIM2Resource
    implements GroupResource {

    private String dName = null;

    private List<String> uMembers = null;

    private List<String> gMembers = null;

    public void setName(String name)
        throws DataSourceException {
        dName = name;
    }

    public String getName()
        throws DataSourceException {
        return dName;
    }

    public void setUserMembers(List<String> idLists)
        throws DataSourceException {
        uMembers = idLists;
    }

    public List<String> getUMembers()
        throws DataSourceException {
        return uMembers;
    }

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException {
        gMembers = idLists;
    }

    public List<String> getGMembers()
        throws DataSourceException {
        return gMembers;
    }

    public List<String> getAllMembers()
        throws DataSourceException {
        List<String> result = new ArrayList<String>(uMembers.size() + gMembers.size());
        result.addAll(uMembers);
        result.addAll(gMembers);
        return result;
    }

}