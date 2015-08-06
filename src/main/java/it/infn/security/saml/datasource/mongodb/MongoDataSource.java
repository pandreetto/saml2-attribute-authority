package it.infn.security.saml.datasource.mongodb;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMConstants;

import com.mongodb.ErrorCategory;
import com.mongodb.MongoClient;
import com.mongodb.MongoException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;

public class MongoDataSource
    implements DataSource {

    private static final Logger logger = Logger.getLogger(MongoDataSource.class.getName());

    private final static String USERS_COLLECTION = "users";

    private final static String GROUPS_COLLECTION = "groups";

    private final static String MEMBRS_COLLECTION = "members";

    private final static String ATTRIBUTE_COLLECTION = "attributes";

    private final static String RESID_FIELD = "_" + SCIMConstants.CommonSchemaConstants.ID;

    private final static String REFID_FIELD = "users_id";

    private final static String SOURCE_FIELD = "source";

    private final static String TARGET_FIELD = "target";

    private final static String TYPE_FIELD = "type";

    /*
     * Definitions for specific attribute structures
     */
    private final static String SPID_ATTR_NAME = "SPIDAttributes";

    private final static String KEY_FIELD = "key";

    private final static String CONTENT_FIELD = "content";

    private final static String ATTR_DESCR_FIELD = "description";

    private MongoClient mongoClient;

    private String dbName;

    private Subject tenant;

    public MongoDataSource() {
        tenant = null;
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

    public DataSource getProxyDataSource(Subject tenant)
        throws DataSourceException {
        if (this.tenant != null)
            throw new DataSourceException("Cannot create proxy from data source");

        MongoDataSource result = new MongoDataSource();
        result.dbName = this.dbName;
        result.mongoClient = this.mongoClient;
        result.tenant = tenant;
        return result;
    }

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        MongoDatabase db = mongoClient.getDatabase(dbName);

        MongoCollection<Document> usersColl = db.getCollection(USERS_COLLECTION);
        MongoCollection<Document> attrColl = db.getCollection(ATTRIBUTE_COLLECTION);

        logger.finer("Query for " + id + " on " + SCIMConstants.UserSchemaConstants.USER_NAME);
        Bson eQuery = Filters.eq(SCIMConstants.UserSchemaConstants.USER_NAME, id);
        MongoCursor<Document> crsr = usersColl.find(eQuery).iterator();
        if (!crsr.hasNext()) {
            logger.info("Entity not found " + id);
            /*
             * TODO empty list or exception?
             */
            return result;
        }

        ObjectId objId = crsr.next().getObjectId(RESID_FIELD);
        logger.finer("Found oid " + objId.toHexString());

        Bson aQuery = Filters.eq(REFID_FIELD, objId);

        if (requiredAttrs != null && requiredAttrs.size() > 0) {

            ArrayList<Bson> orList = new ArrayList<Bson>();
            for (Attribute reqAttr : requiredAttrs) {

                String tmpName = reqAttr.getName();
                List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                if (tmpValues != null && tmpValues.size() > 0) {
                    for (XMLObject xObj : tmpValues) {
                        Bson tmpq = Filters.eq(KEY_FIELD, tmpName);
                        String refValue = xObj.getDOM().getTextContent().trim();
                        tmpq = Filters.and(tmpq, Filters.eq(CONTENT_FIELD, refValue));
                        orList.add(tmpq);
                    }

                } else {
                    orList.add(Filters.eq(KEY_FIELD, tmpName));
                }

            }

            if (orList.size() > 0) {
                Bson tmpq = Filters.or(orList);
                aQuery = Filters.and(aQuery, tmpq);
            }

        }

        for (Document attrItem : attrColl.find(aQuery)) {

            Attribute attribute = attributeBuilder.buildObject();
            attribute.setName(attrItem.getString(KEY_FIELD));
            attribute.setNameFormat(Attribute.BASIC);

            XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(attrItem.getString(CONTENT_FIELD));
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

        MongoDatabase db = mongoClient.getDatabase(dbName);
        MongoCollection<Document> usersColl = db.getCollection(USERS_COLLECTION);

        ObjectId objId = new ObjectId(userId);
        Bson query = Filters.eq(RESID_FIELD, objId);
        MongoCursor<Document> crsr = usersColl.find(query).iterator();
        if (crsr.hasNext()) {
            return userFromDocument(crsr.next(), db);
        }
        logger.fine("Cannot find user " + userId);
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

    public List<User> listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count) {
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
        return createUser(user, false);
    }

    public User createUser(User user, boolean isBulkUserAdd)
        throws CharonException, DuplicateResourceException {

        try {

            MongoDatabase db = mongoClient.getDatabase(dbName);
            MongoCollection<Document> usersColl = db.getCollection(USERS_COLLECTION);
            MongoCollection<Document> membColl = db.getCollection(MEMBRS_COLLECTION);
            MongoCollection<Document> attrColl = db.getCollection(ATTRIBUTE_COLLECTION);

            ObjectId userOid = new ObjectId();
            usersColl.insertOne(documentFromUser(user, userOid));
            logger.info("Created user " + user.getUserName() + " with id " + userOid.toHexString());

            /*
             * TODO verify charon api getGroups
             */
            List<ObjectId> grpOidList = retrieveGroups(user.getGroups(), db);
            for (ObjectId grpOid : grpOidList) {
                Document mDoc = new Document();
                mDoc.append(SOURCE_FIELD, userOid);
                mDoc.append(TARGET_FIELD, grpOid);
                mDoc.append(TYPE_FIELD, 0);
                logger.info("Binding user " + user.getUserName() + " to " + grpOid.toHexString());
                membColl.insertOne(mDoc);
            }

            org.wso2.charon.core.attributes.Attribute extAttribute = user.getAttribute(SPID_ATTR_NAME);
            for (org.wso2.charon.core.attributes.Attribute subAttr : ((MultiValuedAttribute) extAttribute)
                    .getValuesAsSubAttributes()) {
                ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;
                SimpleAttribute keyAttr = (SimpleAttribute) cplxAttr.getSubAttribute(KEY_FIELD);
                SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(CONTENT_FIELD);
                SimpleAttribute frmtAttr = (SimpleAttribute) cplxAttr.getSubAttribute(ATTR_DESCR_FIELD);

                Document mDoc = new Document();
                mDoc.append(REFID_FIELD, userOid);
                mDoc.append(KEY_FIELD, keyAttr.getValue().toString());
                mDoc.append(CONTENT_FIELD, cntAttr.getValue().toString());
                mDoc.append(ATTR_DESCR_FIELD, frmtAttr.getValue().toString());
                attrColl.insertOne(mDoc);

            }

            return user;

        } catch (MongoException mEx) {

            ErrorCategory errCat = ErrorCategory.fromErrorCode(mEx.getCode());
            if (errCat == ErrorCategory.DUPLICATE_KEY) {
                throw new DuplicateResourceException();
            } else {
                throw new CharonException("Query execution error");
            }

        } catch (Exception ex) {

            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new CharonException("Cannot cannot create user " + user.getUserName());

        } finally {
            /*
             * TODO roll-back
             */
        }
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

    public List<Group> listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count) {
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

    private List<ObjectId> getIndirectGroups(MongoCollection<Document> membColl, List<ObjectId> inGrps) {
        HashSet<ObjectId> collected = new HashSet<ObjectId>();
        List<ObjectId> tmpl = inGrps;

        while (tmpl.size() > 0) {
            Bson query1 = Filters.in(SOURCE_FIELD, tmpl);
            Bson query2 = Filters.eq(TYPE_FIELD, 1);
            Bson query = Filters.and(query1, query2);
            FindIterable<Document> crsr = membColl.find(query);
            tmpl = new ArrayList<ObjectId>();
            for (Document membItem : crsr) {
                ObjectId grpOid = membItem.getObjectId(TARGET_FIELD);
                if (!collected.contains(grpOid)) {
                    logger.finer("Found indirect group " + grpOid);
                    tmpl.add(grpOid);
                    collected.add(grpOid);
                }
            }
        }
        return new ArrayList<ObjectId>(collected);
    }

    private List<String> convertOidsIntoStrings(List<ObjectId> inList) {
        ArrayList<String> result = new ArrayList<String>(inList.size());
        for (ObjectId oid : inList) {
            result.add(oid.toHexString());
        }
        return result;
    }

    private User userFromDocument(Document document, MongoDatabase db)
        throws CharonException {
        User result = new User();

        result.setId(document.getObjectId(RESID_FIELD).toHexString());
        result.setUserName(document.getString(SCIMConstants.UserSchemaConstants.USER_NAME));

        MongoCollection<Document> membColl = db.getCollection(MEMBRS_COLLECTION);

        ArrayList<ObjectId> grpIds = new ArrayList<ObjectId>();
        Bson query = Filters.eq(SOURCE_FIELD, document.getObjectId(RESID_FIELD));
        for (Document membItem : membColl.find(query)) {
            grpIds.add(membItem.getObjectId(TARGET_FIELD));
        }
        result.setDirectGroups(convertOidsIntoStrings(grpIds));

        result.setIndirectGroups(convertOidsIntoStrings(getIndirectGroups(membColl, grpIds)));

        return result;
    }

    private Document documentFromUser(User user, ObjectId userOid)
        throws CharonException {

        Document uDoc = new Document();

        uDoc.append(RESID_FIELD, userOid);
        uDoc.append(SCIMConstants.UserSchemaConstants.USER_NAME, user.getUserName());
        uDoc.append(SCIMConstants.UserSchemaConstants.NAME, user.getGivenName() + " " + user.getFamilyName());
        /*
         * TODO complete schema
         */

        return uDoc;

    }

    private List<ObjectId> retrieveGroups(List<String> grpIds, MongoDatabase db) {
        if (grpIds == null) {
            logger.warning("Group list is null");
            return new ArrayList<ObjectId>(0);
        }

        ArrayList<ObjectId> result = new ArrayList<ObjectId>(grpIds.size());
        for (String tmps : grpIds) {
            result.add(new ObjectId(tmps));
        }

        MongoCollection<Document> groupsColl = db.getCollection(GROUPS_COLLECTION);
        Bson query = Filters.in(RESID_FIELD, result);

        result = new ArrayList<ObjectId>(grpIds.size());
        for (Document grpDoc : groupsColl.find(query)) {
            result.add(grpDoc.getObjectId(RESID_FIELD));
        }
        return result;
    }

}