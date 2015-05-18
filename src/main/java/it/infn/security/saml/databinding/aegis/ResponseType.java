package it.infn.security.saml.databinding.aegis;

import it.infn.security.saml.utils.WrapperStreamWriter;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stax.StAXResult;

import org.apache.cxf.aegis.Context;
import org.apache.cxf.aegis.DatabindingException;
import org.apache.cxf.aegis.type.AegisType;
import org.apache.cxf.aegis.xml.MessageReader;
import org.apache.cxf.aegis.xml.MessageWriter;
import org.apache.cxf.aegis.xml.stax.ElementWriter;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

public class ResponseType
    extends AegisType {

    public ResponseType() {
        super();
        setNillable(false);
        setSchemaType(new QName("urn:oasis:names:tc:SAML:2.0:protocol", "Response"));
        setTypeClass(Response.class);
    }

    @Override
    public Object readObject(MessageReader reader, Context context)
        throws DatabindingException {

        throw new DatabindingException("Unsupported operation");
    }

    @Override
    public void writeObject(Object object, MessageWriter writer, Context context)
        throws DatabindingException {

        try {

            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller((Response) object);
            Element resElem = marshaller.marshall((Response) object);

            NamedNodeMap allAttrs = resElem.getAttributes();
            for (int k = 0; k < allAttrs.getLength(); k++) {
                Attr tmpAttr = (Attr) allAttrs.item(k);
                String tmpPref = tmpAttr.getPrefix();
                String tmpName = tmpAttr.getLocalName();

                MessageWriter attrWriter = null;
                if (tmpPref != null && tmpPref.equals(XMLConstants.XMLNS_ATTRIBUTE)) {
                    /*
                     * TODO workaround for the prefix ns1 instead of samlp
                     *      verify signature
                     */
                    attrWriter = writer.getAttributeWriter(tmpName, XMLConstants.XMLNS_ATTRIBUTE_NS_URI);
                } else {
                    attrWriter = writer.getAttributeWriter(tmpName);
                }
                attrWriter.writeValue(tmpAttr.getValue());
            }

            TransformerFactory tfactory = TransformerFactory.newInstance();
            if (tfactory.getFeature(StAXResult.FEATURE) && tfactory.getFeature(DOMSource.FEATURE)) {
                Transformer domToStax = tfactory.newTransformer();
                ElementWriter eWriter = (ElementWriter) writer;
                StAXResult stResult = new StAXResult(new WrapperStreamWriter(eWriter.getXMLStreamWriter()));

                NodeList allElems = resElem.getChildNodes();
                for (int k = 0; k < allElems.getLength(); k++) {
                    domToStax.transform(new DOMSource(allElems.item(k)), stResult);
                }

            } else {
                throw new DatabindingException("Conversion from dom to stream unsupported");
            }

        } catch (DatabindingException dbEx) {
            throw dbEx;
        } catch (Throwable th) {
            throw new DatabindingException("Error building response: " + th.getMessage(), th);
        }
    }

    @Override
    public boolean isComplex() {
        return true;
    }

}
