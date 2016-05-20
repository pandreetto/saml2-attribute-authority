package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;

import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.objects.User;

public class SCIMUser
    extends User
    implements UserResource {

    public static final long serialVersionUID = 1463737051;

    public SCIMUser() {
        super();
    }

    public String getUserId()
        throws DataSourceException {
        try {
            return super.getId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

}