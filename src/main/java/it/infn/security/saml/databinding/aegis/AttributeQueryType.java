package it.infn.security.saml.databinding.aegis;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stax.StAXSource;

import org.apache.cxf.aegis.Context;
import org.apache.cxf.aegis.DatabindingException;
import org.apache.cxf.aegis.type.AegisType;
import org.apache.cxf.aegis.xml.MessageReader;
import org.apache.cxf.aegis.xml.MessageWriter;
import org.apache.ws.commons.schema.XmlSchema;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class AttributeQueryType
    extends AegisType {

    public AttributeQueryType() {
        super();
        setNillable(false);
        setSchemaType(new QName("urn:oasis:names:tc:SAML:2.0:protocol", "AttributeQuery"));
        setTypeClass(AttributeQuery.class);
    }

    @Override
    public Object readObject(MessageReader reader, Context context)
        throws DatabindingException {

        try {

            XMLStreamReader xmlReader = reader.getXMLStreamReader();

            Element element = null;

            TransformerFactory tfactory = TransformerFactory.newInstance();
            if (tfactory.getFeature(StAXSource.FEATURE) && tfactory.getFeature(DOMResult.FEATURE)) {
                Transformer staxToDom = tfactory.newTransformer();
                DOMResult dResult = new DOMResult();
                staxToDom.transform(new StAXSource(xmlReader), dResult);
                Document mainDoc = (Document) dResult.getNode();
                element = mainDoc.getDocumentElement();

            } else {
                throw new DatabindingException("Conversion from stream to dom unsupported");
            }

            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            XMLObject unmarshalled = unmarshaller.unmarshall(element);
            return (AttributeQuery) unmarshalled;

        } catch (DatabindingException dbEx) {
            throw dbEx;
        } catch (Throwable th) {
            throw new DatabindingException("Error parsing attribute query: " + th.getMessage(), th);
        }
    }

    @Override
    public void writeObject(Object object, MessageWriter writer, Context context)
        throws DatabindingException {

        throw new DatabindingException("Unsupported operation");

    }

    @Override
    public boolean isComplex() {
        return true;
    }

    public void writeSchema(XmlSchema root) {
        /*
         * TODO read schema from java resource with XmlSchemaCollection.read(resource)
         */
    }

}
