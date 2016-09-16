package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;

import java.util.ArrayList;
import java.util.List;

public class SCIM2Group
    extends SCIM2Resource
    implements GroupResource {

    private String dName;

    private List<String> uMembers;

    private List<String> gMembers;

    public SCIM2Group() {
        super();

        dName = null;
        uMembers = null;
        gMembers = null;

    }

    public void setName(String name)
        throws DataSourceException {
        if (dName != null) {
            throw new DataSourceException("Cannot change group name");
        }
        dName = name;
    }

    public String getName()
        throws DataSourceException {
        return dName;
    }

    public void setUserMembers(List<String> idLists)
        throws DataSourceException {
        if (uMembers != null) {
            resourceUpdated();
        }
        uMembers = idLists;
    }

    public List<String> getUMembers()
        throws DataSourceException {
        if (uMembers == null) {
            uMembers = new ArrayList<String>();
        }
        return uMembers;
    }

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException {
        if (gMembers != null) {
            resourceUpdated();
        }
        gMembers = idLists;
    }

    public List<String> getGMembers()
        throws DataSourceException {
        if (gMembers == null) {
            gMembers = new ArrayList<String>();
        }
        return gMembers;
    }

    public List<String> getAllMembers()
        throws DataSourceException {

        List<String> result = new ArrayList<String>(getUMembers().size() + getGMembers().size());
        result.addAll(uMembers);
        result.addAll(gMembers);
        return result;
    }

    public String getType() {
        return SCIMCoreConstants.GROUP_TAG;
    }

}