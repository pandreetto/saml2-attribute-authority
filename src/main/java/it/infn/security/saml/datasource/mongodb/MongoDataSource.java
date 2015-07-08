package it.infn.security.saml.datasource.mongodb;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;

import java.util.ArrayList;
import java.util.List;

import org.bson.Document;
import org.bson.conversions.Bson;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;

public class MongoDataSource
    implements DataSource {

    private final static String ATTR_COLL = "attributes";

    private final static String UID_FIELD = "uid";

    private final static String NAME_FIELD = "name";

    private final static String VALUE_FIELD = "value";

    private final static String TYPE_FIELD = "type";

    private MongoClient mongoClient;

    private String dbName;

    public MongoDataSource() {
    }

    public void init()
        throws DataSourceException {

        try {
            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            dbName = config.getDataSourceParam("db_name");
        } catch (Throwable th) {
            throw new DataSourceException("Cannot initialize database", th);
        }

        mongoClient = new MongoClient();

    }

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        MongoDatabase db = mongoClient.getDatabase(dbName);
        MongoCollection<Document> attrColl = db.getCollection(ATTR_COLL);

        Bson query = Filters.eq(UID_FIELD, id);

        if (requiredAttrs != null && requiredAttrs.size() > 0) {

            ArrayList<Bson> orList = new ArrayList<Bson>();
            for (Attribute reqAttr : requiredAttrs) {

                String tmpName = reqAttr.getName();
                List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                if (tmpValues != null && tmpValues.size() > 0) {
                    for (XMLObject xObj : tmpValues) {
                        Bson tmpq = Filters.eq(NAME_FIELD, tmpName);
                        String refValue = xObj.getDOM().getTextContent().trim();
                        tmpq = Filters.and(tmpq, Filters.eq(VALUE_FIELD, refValue));
                        orList.add(tmpq);
                    }

                } else {
                    orList.add(Filters.eq(NAME_FIELD, tmpName));
                }

            }

            if (orList.size() > 0) {
                Bson tmpq = Filters.or(orList);
                query = Filters.and(query, tmpq);
            }

        }

        for (Document attrItem : attrColl.find(query)) {

            Attribute attribute = attributeBuilder.buildObject();
            attribute.setName(attrItem.getString(NAME_FIELD));
            attribute.setNameFormat(attrItem.getString(TYPE_FIELD));

            XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(attrItem.getString(VALUE_FIELD));
            attribute.getAttributeValues().add(attributeValue);

            result.add(attribute);

        }

        return result;
    }

    public void close()
        throws DataSourceException {

        mongoClient.close();

    }

    public User getUser(String userId)
        throws CharonException {
        return null;
    }

    public List<User> listUsers()
        throws CharonException {
        return null;
    }

    public List<User> listUsersByAttribute(org.wso2.charon.core.attributes.Attribute attribute) {
        return null;
    }

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<User> listUsersBySort(String sortBy, String sortOrder) {
        return null;
    }

    public List<User> listUsersWithPagination(int startIndex, int count) {
        return null;
    }

    public User updateUser(User user)
        throws CharonException {
        return null;
    }

    public User updateUser(List<org.wso2.charon.core.attributes.Attribute> updatedAttributes) {
        return null;
    }

    public void deleteUser(String userId)
        throws NotFoundException, CharonException {

    }

    public User createUser(User user)
        throws CharonException, DuplicateResourceException {
        return null;
    }

    public User createUser(User user, boolean isBulkUserAdd)
        throws CharonException, DuplicateResourceException {
        return null;
    }

    public Group getGroup(String groupId)
        throws CharonException {
        return null;
    }

    public List<Group> listGroups()
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByAttribute(org.wso2.charon.core.attributes.Attribute attribute)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        return null;
    }

    public Group createGroup(Group group)
        throws CharonException, DuplicateResourceException {
        return null;
    }

    public Group updateGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group patchGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group updateGroup(List<org.wso2.charon.core.attributes.Attribute> attributes)
        throws CharonException {
        return null;
    }

    public void deleteGroup(String groupId)
        throws NotFoundException, CharonException {

    }

}