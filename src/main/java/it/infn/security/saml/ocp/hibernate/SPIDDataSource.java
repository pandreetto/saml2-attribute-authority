package it.infn.security.saml.ocp.hibernate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.hibernate.Query;
import org.hibernate.Session;
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
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.hibernate.HibernateDataSource;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;

public class SPIDDataSource
    extends HibernateDataSource {

    private static final Logger logger = Logger.getLogger(SPIDDataSource.class.getName());

    private final static String SPID_ATTR_NAME = "SPIDAttributes";

    private final static String KEY_FIELD = "key";

    private final static String CONTENT_FIELD = "content";

    private final static String ATTR_DESCR_FIELD = "description";

    private Subject tenant;

    public SPIDDataSource() {
        super();
    }

    public DataSource getProxyDataSource(Subject tenant)
        throws DataSourceException {
        if (this.tenant != null)
            throw new DataSourceException("Cannot create proxy from data source");

        SPIDDataSource result = (SPIDDataSource) new SPIDDataSource();
        result.tenant = tenant;
        return result;
    }

    public Subject getTenant() {
        return tenant;
    }

    protected List<Attribute> buildAttributeList(Session session, HashSet<String> allIds, List<Attribute> reqAttrs) {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        HashMap<String, Object> qArgs = new HashMap<String, Object>();
        StringBuffer queryStr = new StringBuffer("SELECT qAttributes");
        queryStr.append(" FROM ResourceEntity as qRes INNER JOIN qRes.attributes as qAttributes");

        queryStr.append(" WHERE qRes.id IN (:resourceIds)");
        qArgs.put("resourceIds", allIds);

        if (reqAttrs != null && reqAttrs.size() > 0) {
            queryStr.append(" AND (");
            int keyNum = 0;
            for (Attribute reqAttr : reqAttrs) {
                String tmpName = reqAttr.getName();
                List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                if (keyNum > 0) {
                    queryStr.append(" OR");
                }
                String keyTag = "key_" + keyNum;
                keyNum++;

                if (tmpValues != null && tmpValues.size() > 0) {
                    int cntNum = 0;
                    for (XMLObject xObj : tmpValues) {

                        if (cntNum > 0) {
                            queryStr.append(" OR");
                        }
                        String refValue = xObj.getDOM().getTextContent().trim();

                        queryStr.append(" (qAttributes.attributeId.key = :").append(keyTag);
                        qArgs.put(keyTag, tmpName);

                        String cntTag = "cnt_" + keyNum + "_" + cntNum;
                        queryStr.append(" AND qAttributes.attributeId.content = :");
                        queryStr.append(cntTag).append(")");
                        qArgs.put(cntTag, refValue);
                        cntNum++;
                    }
                } else {
                    queryStr.append(" qAttributes.attributeId.key = :").append(keyTag);
                    qArgs.put(keyTag, tmpName);
                }
            }

            queryStr.append(")");
        }

        Query query = session.createQuery(queryStr.toString());
        query.setProperties(qArgs);

        @SuppressWarnings("unchecked")
        List<AttributeEntity> filteredAttrs = query.list();

        HashMap<String, Attribute> resultTable = new HashMap<String, Attribute>();
        for (AttributeEntity attrEnt : filteredAttrs) {

            String attrKey = attrEnt.getAttributeId().getKey();
            Attribute attribute = null;
            if (resultTable.containsKey(attrKey)) {
                attribute = resultTable.get(attrKey);
            } else {
                attribute = attributeBuilder.buildObject();
                attribute.setName(attrKey);
                attribute.setNameFormat(Attribute.BASIC);
                resultTable.put(attrKey, attribute);
            }

            XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(attrEnt.getAttributeId().getContent());
            attribute.getAttributeValues().add(attributeValue);

        }

        for (Attribute tmpAttr : resultTable.values()) {
            result.add(tmpAttr);
        }

        return result;
    }

    protected Set<AttributeEntity> getExtendedAttributes(Session session, AbstractSCIMObject resource)
        throws CharonException, NotFoundException {

        Set<AttributeEntity> result = new HashSet<AttributeEntity>();

        if (!resource.isAttributeExist(SPID_ATTR_NAME)) {
            return result;
        }

        org.wso2.charon.core.attributes.Attribute extAttribute = resource.getAttribute(SPID_ATTR_NAME);
        List<org.wso2.charon.core.attributes.Attribute> allSubAttrs = ((MultiValuedAttribute) extAttribute)
                .getValuesAsSubAttributes();
        for (org.wso2.charon.core.attributes.Attribute subAttr : allSubAttrs) {
            ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;
            SimpleAttribute keyAttr = (SimpleAttribute) cplxAttr.getSubAttribute(KEY_FIELD);
            SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(CONTENT_FIELD);
            SimpleAttribute descrAttr = (SimpleAttribute) cplxAttr.getSubAttribute(ATTR_DESCR_FIELD);

            AttributeEntity attrEnt = new AttributeEntity();
            AttributeEntityId attrEntId = new AttributeEntityId();
            attrEntId.setKey(keyAttr.getStringValue());
            attrEntId.setContent(cntAttr.getStringValue());
            attrEnt.setAttributeId(attrEntId);
            attrEnt.setDescription(descrAttr.getStringValue());

            /*
             * TODO check for attribute auto-saving
             */
            if (session.get(AttributeEntity.class, attrEntId) == null) {
                logger.info("Saving attribute " + attrEnt.getAttributeId().getKey());
                session.save(attrEnt);
            }

            result.add(attrEnt);

        }

        return result;
    }

}