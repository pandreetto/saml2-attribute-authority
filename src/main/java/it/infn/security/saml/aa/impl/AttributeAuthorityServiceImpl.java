package it.infn.security.saml.aa.impl;

import it.infn.security.saml.aa.AttributeAuthorityService;
import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.handler.SAML2Handler;
import it.infn.security.saml.handler.SAML2HandlerFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.security.auth.Subject;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;

public class AttributeAuthorityServiceImpl
    implements AttributeAuthorityService {

    public static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    public Response attributeQuery(AttributeQuery query) {

        try {

            Response response = this.newResponse(query.getID());
            Issuer responseIssuer = this.newIssuer();
            response.setIssuer(responseIssuer);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();

            if (query.getVersion() != SAMLVersion.VERSION_20) {
                throw new CodedException("Unsupported version", StatusCode.VERSION_MISMATCH_URI);
            }

            DataSource dataSource = DataSourceFactory.getDataSource();
            SAML2Handler handler = SAML2HandlerFactory.getHandler();

            /*
             * TODO validate signature
             */

            handler.checkRequest(query);

            Subject requester = identityManager.authenticate();

            AccessConstraints constraints = accessManager.authorizeAttributeQuery(requester, query);

            String sbjID = handler.getSubjectID(query);

            List<Attribute> queryAttrs = constraints.filterAttributes(query.getAttributes());
            List<Attribute> userAttrs = dataSource.findAttributes(sbjID, queryAttrs);

            handler.fillInResponse(response, userAttrs, query);

            signAssertions(response, requester);

            Status status = this.newStatus();
            response.setStatus(status);

            return response;

        } catch (Throwable th) {

            th.printStackTrace();

            Response response = this.newResponse(query.getID());

            Issuer responseIssuer = this.newIssuer();
            response.setIssuer(responseIssuer);

            Status status = this.newStatus(th);
            response.setStatus(status);

            return response;

        }

    }

    private Response newResponse(String respID) {

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        response.setID("_" + UUID.randomUUID().toString());
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(respID);

        return response;
    }

    private Issuer newIssuer() {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

        IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer responseIssuer = issuerBuilder.buildObject();

        try {
            responseIssuer.setFormat(configuration.getAuthorityIDFormat());
            responseIssuer.setValue(configuration.getAuthorityID());
        } catch (ConfigurationException cfgEx) {
            /*
             * TODO log
             */
        }

        return responseIssuer;

    }

    private Status newStatus() {
        StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        status.setStatusCode(statusCode);
        return status;
    }

    private Status newStatus(Throwable th) {

        StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();

        if (th.getMessage() != null) {
            StatusMessageBuilder statusMessageBuilder = (StatusMessageBuilder) builderFactory
                    .getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
            StatusMessage statusMessage = statusMessageBuilder.buildObject();
            statusMessage.setMessage(th.getMessage());
            status.setStatusMessage(statusMessage);
        }

        StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();

        if (th.getClass() == CodedException.class) {
            CodedException handlerEx = (CodedException) th;
            statusCode.setValue(handlerEx.getStatusCode());

            String subCode = handlerEx.getSubStatusCode();
            if (subCode != null) {
                StatusCode subStatusCode = statusCodeBuilder.buildObject();
                subStatusCode.setValue(subCode);
                statusCode.setStatusCode(subStatusCode);
            }

        } else {
            statusCode.setValue(StatusCode.RESPONDER_URI);
        }

        status.setStatusCode(statusCode);

        return status;

    }

    private void signAssertions(Response response, Subject requester)
        throws SecurityException, ConfigurationException, SignatureException, MarshallingException {

        List<Assertion> assertions = response.getAssertions();
        if (assertions.size() == 0) {
            throw new SecurityException("Missing assertion in response");
        }

        X509Certificate subjectCertificate = null;
        Set<X509Certificate[]> allChain = requester.getPublicCredentials(X509Certificate[].class);
        for (X509Certificate[] peerChain : allChain) {
            subjectCertificate = peerChain[0];
        }
        if (subjectCertificate == null) {
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

        X509Certificate srvCert = config.getServiceCertificate();
        PrivateKey srvKey = config.getServicePrivateKey();
        Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);

        KeyInfoGeneratorManager keyInfoGeneratorManager = new KeyInfoGeneratorManager();
        keyInfoGeneratorManager.registerFactory(x509KeyInfoGeneratorFactory);

        KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(peerCredential);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        for (Assertion assertion : assertions) {
            SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory
                    .getBuilder(Signature.DEFAULT_ELEMENT_NAME);
            Signature assertionSignature = signatureBuilder.buildObject();
            assertionSignature.setSigningCredential(credential);
            assertionSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            assertionSignature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);

            KeyInfo serviceKeyInfo = keyInfoGenerator.generate(credential);
            assertionSignature.setKeyInfo(serviceKeyInfo);

            assertion.setSignature(assertionSignature);
            /*
             * TODO verify workaround
             */
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            marshallerFactory.getMarshaller(assertion).marshall(assertion);

            Signer.signObject(assertionSignature);

        }
    }

}
