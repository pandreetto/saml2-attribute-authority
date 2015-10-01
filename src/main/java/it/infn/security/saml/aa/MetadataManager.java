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
import it.infn.security.saml.utils.charon.JAXRSResponseBuilder;

import java.security.PrivateKey;
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
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.Canonicalizer;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeProfile;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
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
            PrivateKey srvKey = configuration.getServicePrivateKey();
            Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

            EntityDescriptor entDescr = SAML2ObjectBuilder.buildEntityDescriptor();
            entDescr.setID(UUID.randomUUID().toString());
            entDescr.setEntityID(configuration.getAuthorityID());
            long dtime = configuration.getMetadataDuration();
            if (dtime > 0) {
                DateTime expDate = new DateTime(System.currentTimeMillis() + (dtime * 1000));
                entDescr.setValidUntil(expDate);
            }
            /*
             * TODO set organization and contact persons
             */

            AttributeAuthorityDescriptor aaDescr = SAML2ObjectBuilder.buildAttributeAuthorityDescriptor();
            for (String proto : schemaManager.getSupportedProtocols()) {
                aaDescr.addSupportedProtocol(proto);
            }
            entDescr.getRoleDescriptors().add(aaDescr);

            AttributeService attrService = SAML2ObjectBuilder.buildAttributeService();
            aaDescr.getAttributeServices().add(attrService);

            NameIDFormat nidFormat = SAML2ObjectBuilder.buildNameIDFormat();
            aaDescr.getNameIDFormats().add(nidFormat);

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
            KeyInfo keyInfo = SAML2ObjectBuilder.buildKeyInfo();
            KeyName keyName = SAML2ObjectBuilder.buildKeyName();
            X509Data x509Data = SAML2ObjectBuilder.buildX509Data();
            X509SubjectName x509Sbj = SAML2ObjectBuilder.buildX509SubjectName();
            org.opensaml.xml.signature.X509Certificate x509Cert = SAML2ObjectBuilder.buildX509Certificate();
            /*
             * TODO verify keyName
             */
            keyName.setValue(srvCert.getSubjectDN().getName());
            x509Sbj.setValue(srvCert.getSubjectDN().getName());
            x509Data.getX509SubjectNames().add(x509Sbj);
            /*
             * TODO encode cert in base64
             */
            x509Cert.setValue("");
            keyInfo.getKeyNames().add(keyName);
            keyInfo.getX509Datas().add(x509Data);
            keyDescr.setKeyInfo(keyInfo);
            aaDescr.getKeyDescriptors().add(keyDescr);

            Signature entSignature = SAML2ObjectBuilder.buildSignature();
            entSignature.setSigningCredential(credential);
            entSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            entSignature.setSignatureAlgorithm(configuration.getSignatureAlgorithm());

            entDescr.setSignature(entSignature);

            String payload = buildPayload(entDescr, entSignature);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, "text/xml");
            return JAXRSResponseBuilder.buildResponse(ResponseCodeConstants.CODE_OK, httpHeaders, payload);

        } catch (Exception ex) {
            /*
             * TODO verify output format
             */
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, null));
        }
    }

    private String buildPayload(EntityDescriptor entDescr, Signature entSignature)
        throws MarshallingException, SignatureException, ParserConfigurationException {
        /*
         * TODO verify workaround
         */
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(entDescr);
        marshaller.marshall(entDescr);

        Signer.signObject(entSignature);

        DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document rootElement = docBuilder.newDocument();
        marshaller.marshall(entDescr, rootElement);
        DOMImplementationLS lsImpl = (DOMImplementationLS) rootElement.getImplementation();
        LSSerializer domSerializer = lsImpl.createLSSerializer();
        return domSerializer.writeToString(rootElement);

    }
}