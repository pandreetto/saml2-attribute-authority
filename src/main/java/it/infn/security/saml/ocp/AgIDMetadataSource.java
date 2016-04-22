package it.infn.security.saml.ocp;

import it.infn.security.saml.spmetadata.MetadataSource;
import it.infn.security.saml.spmetadata.MetadataSourceException;
import it.infn.security.saml.spmetadata.SPMetadata;
import it.infn.security.saml.utils.SAML2ObjectBuilder;

import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.io.Unmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class AgIDMetadataSource
    implements MetadataSource {

    private static final String XPATH_MD_QUERY = "/FederationRegistry/AuthorityInfo/MetadataProviderURL";

    private static final String REQ_PROTO = "urn:oasis:names:tc:SAML:2.0:protocol";

    private static final Logger logger = Logger.getLogger(AgIDMetadataSource.class.getName());

    private String registryHost;

    private int registryPort;

    private String registryPath;

    private DocumentBuilderFactory dbf;

    private XPathExpression registryExpr;

    /*
     * TODO replace with a real cache system
     */
    private HashMap<String, SPMetadata> spCache;

    public void init()
        throws MetadataSourceException {

        try {

            dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setNamespaceAware(true);

            registryExpr = XPathFactory.newInstance().newXPath().compile(XPATH_MD_QUERY);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new MetadataSourceException(ex.getMessage(), ex);
        }

        spCache = new HashMap<String, SPMetadata>();

    }

    public SPMetadata getMetadata(String entityId)
        throws MetadataSourceException {

        synchronized (spCache) {

            if (!spCache.containsKey(entityId)) {

                String mdLocation = getSPMetadataURL(entityId);

                spCache.put(entityId, getSPMetadata(mdLocation));

            }
            return spCache.get(entityId);
        }

    }

    public void close()
        throws MetadataSourceException {

        spCache.clear();

    }

    public int getLoadPriority() {
        return 0;
    }

    private String getSPMetadataURL(String entityId)
        throws MetadataSourceException {

        try {

            String queryStr = "entityId=" + entityId;
            URI queryURI = new URI("https", null, registryHost, registryPort, registryPath, queryStr, null);
            logger.fine("Contacting registry " + queryURI.toString());

            Element response = getXMLDocument(queryURI).getDocumentElement();

            NodeList mdList = (NodeList) registryExpr.evaluate(response, XPathConstants.NODESET);
            if (mdList.getLength() > 0) {
                String spURL = ((Element) mdList.item(0)).getTextContent();
                logger.fine("Found URL " + spURL + " for " + entityId);
                return spURL;
            }

        } catch (MetadataSourceException mdEx) {
            throw mdEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
        }

        throw new MetadataSourceException("Cannot retrieve metadata location for " + entityId);

    }

    private SPMetadata getSPMetadata(String mdLocation)
        throws MetadataSourceException {

        try {

            URI mdURI = new URI(mdLocation);
            logger.fine("Contacting SP " + mdLocation);

            Element response = getXMLDocument(mdURI).getDocumentElement();

            Unmarshaller unmarshaller = SAML2ObjectBuilder.getUnmarshaller(response);
            EntityDescriptor entDescr = (EntityDescriptor) unmarshaller.unmarshall(response);

            /*
             * TODO verify metadata signature against AgID certificate
             */

            SPSSODescriptor spDescr = entDescr.getSPSSODescriptor(REQ_PROTO);
            SPMetadata result = new SPMetadata();

            result.setExpiration(entDescr.getValidUntil().getMillis());

            List<AttributeConsumingService> attrCS = spDescr.getAttributeConsumingServices();
            for (AttributeConsumingService acsItem : attrCS) {
                for (RequestedAttribute rAttr : acsItem.getRequestAttributes()) {
                    result.addAttribute(rAttr.getName());
                }
            }
            return result;

        } catch (MetadataSourceException mdEx) {
            throw mdEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
        }

        throw new MetadataSourceException("Cannot retrieve metadata from " + mdLocation);

    }

    private Document getXMLDocument(URI location)
        throws MetadataSourceException {

        InputStream inStr = null;
        HttpsURLConnection urlConn = null;

        try {

            urlConn = (HttpsURLConnection) location.toURL().openConnection();
            urlConn.setRequestMethod("GET");
            urlConn.connect();

            if (urlConn.getResponseCode() < 400) {
                inStr = urlConn.getInputStream();
                return dbf.newDocumentBuilder().parse(inStr);
            }

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
        } finally {

            if (inStr != null) {
                try {
                    inStr.close();
                } catch (Throwable th) {
                    logger.log(Level.SEVERE, th.getMessage(), th);
                }
            }

            if (urlConn != null)
                urlConn.disconnect();

        }

        throw new MetadataSourceException("Cannot retrieve metadata for " + location.toString());

    }

}