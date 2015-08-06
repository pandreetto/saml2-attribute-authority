package it.infn.security.saml.datasource;

import java.util.List;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.Attribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public interface DataSource
    extends UserManager {

    public void init()
        throws DataSourceException;

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException;

    public List<User> listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException;

    public List<Group> listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException;

    public void close()
        throws DataSourceException;

    public DataSource getProxyDataSource(Subject tenant)
        throws DataSourceException;

}