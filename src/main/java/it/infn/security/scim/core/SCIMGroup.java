package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;

import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.objects.Group;

public class SCIMGroup
    extends Group
    implements GroupResource {

    public static final long serialVersionUID = 1463734695;

    public SCIMGroup() {
        super();
    }

    public String getGroupId()
        throws DataSourceException {
        try {
            return super.getId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

}