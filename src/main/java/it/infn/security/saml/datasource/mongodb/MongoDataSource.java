package it.infn.security.saml.datasource.mongodb;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;

import java.util.ArrayList;
import java.util.List;

import org.bson.Document;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

public class MongoDataSource
    implements DataSource {

    private MongoClient mongoClient;

    public MongoDataSource() {
    }
    
    public void init()
            throws DataSourceException {
        
        /*
         * TODO read parameters from configuration
         */
        mongoClient = new MongoClient();

    }

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        MongoDatabase db = mongoClient.getDatabase("test");
        MongoCollection<Document> attrColl = db.getCollection("attributes");

        for (Document attrItem : attrColl.find(new Document("uid", id))) {

            Attribute attribute = attributeBuilder.buildObject();
            attribute.setName(attrItem.getString("name"));
            attribute.setNameFormat(attrItem.getString("type"));

            XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(attrItem.getString("value"));
            attribute.getAttributeValues().add(attributeValue);

            result.add(attribute);

        }

        return result;
    }

    public void close()
        throws DataSourceException {

        mongoClient.close();

    }

}