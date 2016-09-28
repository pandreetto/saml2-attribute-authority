package it.infn.security.saml.ocp;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.AccessedExpiryPolicy;
import javax.cache.expiry.Duration;
import javax.net.ssl.HttpsURLConnection;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.io.Unmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.spmetadata.MetadataSource;
import it.infn.security.saml.spmetadata.MetadataSourceException;
import it.infn.security.saml.spmetadata.SPMetadata;
import it.infn.security.saml.utils.SAML2ObjectBuilder;

public class AgIDMetadataSource
    implements MetadataSource {

    private static final String REQ_PROTO = "urn:oasis:names:tc:SAML:2.0:protocol";

    private static final String CACHE_NAME = "metadata";

    private static final String AGID_NS = "http://www.agid.gov.it/spid";

    private static final String REGISTRY_URL = "agid.registry.url";

    private static final String CACHE_DURATION = "agid.cache.duration";

    private static final Logger logger = Logger.getLogger(AgIDMetadataSource.class.getName());

    private String registryURL;

    private DocumentBuilderFactory dbf;

    private CacheManager cManager;

    private Cache<String, SPMetadata> spCache;

    public void init()
        throws MetadataSourceException {

        try {

            dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setNamespaceAware(true);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String localURL = configuration.getAuthorityURL() + "/registry";
            registryURL = configuration.getMetadataSourceParam(REGISTRY_URL, localURL);

            cManager = Caching.getCachingProvider().getCacheManager();
            logger.fine("Using cache manager implementation: " + cManager.getClass().getName());

            MutableConfiguration<String, SPMetadata> mConf = new MutableConfiguration<>();
            mConf.setTypes(String.class, SPMetadata.class);
            mConf.setStoreByValue(true);
            int tmpDur = configuration.getMetadataSourceParamAsInt(CACHE_DURATION, 1);
            Duration cDuration = new Duration(TimeUnit.SECONDS, tmpDur);
            mConf.setExpiryPolicyFactory(AccessedExpiryPolicy.factoryOf(cDuration));

            spCache = cManager.createCache(CACHE_NAME, mConf);
            logger.info("Created cache: " + CACHE_NAME);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new MetadataSourceException(ex.getMessage(), ex);
        }

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

        cManager.destroyCache(CACHE_NAME);

    }

    public int getLoadPriority() {
        return 0;
    }

    private String getSPMetadataURL(String entityId)
        throws MetadataSourceException {

        try {

            URI queryURI = new URI(registryURL + "?entityId=" + entityId);

            /*
             * TODO set to fine
             */
            logger.info("Contacting registry " + queryURI.toString());

            Element fedRegistry = getXMLDocument(queryURI).getDocumentElement();

            NodeList tmpList1 = fedRegistry.getElementsByTagNameNS(AGID_NS, "AuthorityInfo");
            if (tmpList1.getLength() > 0) {
                Element authInfo = (Element) tmpList1.item(0);
                NodeList tmpList2 = authInfo.getElementsByTagNameNS(AGID_NS, "MetadataProviderURL");

                if (tmpList2.getLength() > 0) {
                    Element mdProviderURL = (Element) tmpList2.item(0);
                    String spURL = mdProviderURL.getTextContent();
                    logger.fine("Found URL " + spURL + " for " + entityId);
                    return spURL;
                }
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
            if (spDescr == null) {
                throw new MetadataSourceException("Cannot find SPSSODescriptor");
            }
            SPMetadata result = new SPMetadata();

            List<AttributeConsumingService> attrCS = spDescr.getAttributeConsumingServices();
            for (AttributeConsumingService acsItem : attrCS) {
                for (RequestedAttribute rAttr : acsItem.getRequestAttributes()) {
                    result.addAttribute(rAttr.getName());
                    logger.fine("Attribute from " + mdLocation + ": " + rAttr.getName());
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