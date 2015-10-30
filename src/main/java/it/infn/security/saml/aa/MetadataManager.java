package it.infn.security.saml.aa;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerFactory;
import it.infn.security.saml.utils.SAML2ObjectBuilder;
import it.infn.security.saml.utils.SCIMUtils;
import it.infn.security.saml.utils.SignUtils;
import it.infn.security.saml.utils.charon.JAXRSResponseBuilder;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeProfile;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.xml.io.Marshaller;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.schema.SCIMConstants;

@Path("/service_metadata")
public class MetadataManager {

    private static final Logger logger = Logger.getLogger(MetadataManager.class.getName());

    @GET
    @Produces("text/xml")
    public Response getAttributeNames() {

        try {

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            DataSource dataSource = DataSourceFactory.getDataSource();

            X509Certificate srvCert = configuration.getServiceCertificate();

            EntityDescriptor entDescr = SAML2ObjectBuilder.buildEntityDescriptor();
            entDescr.setID(UUID.randomUUID().toString());
            entDescr.setEntityID(configuration.getAuthorityID());
            long dtime = configuration.getMetadataDuration();
            if (dtime > 0) {
                DateTime expDate = new DateTime(System.currentTimeMillis() + (dtime * 1000));
                entDescr.setValidUntil(expDate);
            }

            for (ContactPerson contact : configuration.getContacts()) {
                entDescr.getContactPersons().add(contact);
            }

            /*
             * TODO missing organization
             */

            AttributeAuthorityDescriptor aaDescr = SAML2ObjectBuilder.buildAttributeAuthorityDescriptor();
            for (String proto : schemaManager.getSupportedProtocols()) {
                aaDescr.addSupportedProtocol(proto);
            }
            entDescr.getRoleDescriptors().add(aaDescr);

            AttributeService attrService = SAML2ObjectBuilder.buildAttributeService();
            attrService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
            attrService.setLocation(configuration.getAuthorityURL() + "/samlAA");
            aaDescr.getAttributeServices().add(attrService);

            for (String nIdFormat : schemaManager.getSupportedNameIDFormats()) {
                NameIDFormat nidFormat = SAML2ObjectBuilder.buildNameIDFormat();
                nidFormat.setFormat(nIdFormat);
                aaDescr.getNameIDFormats().add(nidFormat);
            }

            for (String prof : schemaManager.getSupportedAttributeProfiles()) {
                AttributeProfile attrProfile = SAML2ObjectBuilder.buildAttributeProfile();
                attrProfile.setProfileURI(prof);
                aaDescr.getAttributeProfiles().add(attrProfile);
            }

            for (AttributeNameInterface name : dataSource.getAttributeNames()) {
                Attribute nameAttr = SAML2ObjectBuilder.buildAttribute();
                nameAttr.setName(name.getNameId());
                nameAttr.setNameFormat(name.getNameFormat());
                nameAttr.setFriendlyName(name.getFriendlyName());
                aaDescr.getAttributes().add(nameAttr);
            }

            KeyDescriptor keyDescr = SAML2ObjectBuilder.buildKeyDescriptor();
            keyDescr.setKeyInfo(SignUtils.buildKeyInfo(srvCert));
            aaDescr.getKeyDescriptors().add(keyDescr);

            SignUtils.signObject(entDescr);

            DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document rootElement = docBuilder.newDocument();
            Marshaller marshaller = SAML2ObjectBuilder.getMarshaller(entDescr);
            marshaller.marshall(entDescr, rootElement);
            DOMImplementationLS lsImpl = (DOMImplementationLS) rootElement.getImplementation();
            LSSerializer domSerializer = lsImpl.createLSSerializer();
            String payload = domSerializer.writeToString(rootElement);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, "text/xml");
            return JAXRSResponseBuilder.buildResponse(ResponseCodeConstants.CODE_OK, httpHeaders, payload);

        } catch (Exception ex) {
            /*
             * TODO verify output format change error message in response
             */
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, null));
        }
    }
}