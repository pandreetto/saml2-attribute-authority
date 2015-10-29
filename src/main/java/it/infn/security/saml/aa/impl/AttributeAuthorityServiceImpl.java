package it.infn.security.saml.aa.impl;

import it.infn.security.saml.aa.AttributeAuthorityService;
import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.AttributeQueryParameters;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;
import it.infn.security.saml.utils.SAML2ObjectBuilder;
import it.infn.security.saml.utils.SignUtils;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;

public class AttributeAuthorityServiceImpl
    implements AttributeAuthorityService {

    private static final Logger logger = Logger.getLogger(AttributeAuthorityServiceImpl.class.getName());

    public Response attributeQuery(AttributeQuery query) {

        Response response = SAML2ObjectBuilder.buildResponse();
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(query.getID());

        try {

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            DataSource dataSource = DataSourceFactory.getDataSource();

            response.setID(schemaManager.generateResponseID());

            Issuer responseIssuer = newIssuer(configuration);
            response.setIssuer(responseIssuer);

            if (query.getVersion() != SAMLVersion.VERSION_20) {
                throw new CodedException("Unsupported version", StatusCode.VERSION_MISMATCH_URI);
            }

            schemaManager.checkRequest(query);

            Subject requester = identityManager.authenticate();

            Signature signature = query.getSignature();
            if (signature == null && schemaManager.requiredSignedQuery()) {
                throw new CodedException("Missing signature in query", StatusCode.RESPONDER_URI);
            }
            if (signature != null) {
                verifySignature(signature, requester);
            }

            String samlId = query.getSubject().getNameID().getValue();
            String userId = dataSource.samlId2UserId(samlId);
            if (userId == null) {
                throw new DataSourceException("User not found", StatusCode.RESPONDER_URI,
                        StatusCode.UNKNOWN_PRINCIPAL_URI);
            }

            AttributeQueryParameters params = new AttributeQueryParameters(userId);
            AccessConstraints constraints = accessManager.authorizeAttributeQuery(requester, params);

            List<Attribute> queryAttrs = constraints.filterAttributes(query.getAttributes());
            List<Attribute> userAttrs = dataSource.findAttributes(userId, queryAttrs);

            String respDestination = schemaManager.getResponseDestination();
            if (respDestination != null) {
                response.setDestination(respDestination);
            }

            /* Building the assertion */
            /*
             * TODO verify multiple assertions in response
             */
            Assertion assertion = SAML2ObjectBuilder.buildAssertion();
            assertion.setID(schemaManager.generateAssertionID());
            assertion.setIssueInstant(new DateTime());

            Issuer assertionIssuer = newIssuer(configuration);
            assertion.setIssuer(assertionIssuer);

            AttributeStatement attributeStatement = SAML2ObjectBuilder.buildAttributeStatement();
            attributeStatement.getAttributes().addAll(userAttrs);
            assertion.getAttributeStatements().add(attributeStatement);

            if (schemaManager.requiredSignedAssertion()) {
                SignUtils.signObject(assertion);
            }

            response.getAssertions().add(assertion);

            Status status = SAML2ObjectBuilder.buildStatus();
            StatusCode statusCode = SAML2ObjectBuilder.buildStatusCode();
            statusCode.setValue(StatusCode.SUCCESS_URI);
            status.setStatusCode(statusCode);
            response.setStatus(status);

            if (schemaManager.requiredSignedResponse()) {
                SignUtils.signObject(response);
            }

        } catch (SchemaManagerException cEx) {

            if (response.getID() == null) {
                response.setID("_" + UUID.randomUUID().toString());
            }
            Status status = this.newStatus(cEx);
            response.setStatus(status);

        } catch (CodedException cEx) {

            Status status = this.newStatus(cEx);
            response.setStatus(status);

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

            Status status = this.newStatus(th);
            response.setStatus(status);

        }

        return response;

    }

    private Issuer newIssuer(AuthorityConfiguration configuration)
        throws ConfigurationException {

        Issuer responseIssuer = SAML2ObjectBuilder.buildIssuer();

        try {
            responseIssuer.setFormat(configuration.getAuthorityIDFormat());
            responseIssuer.setValue(configuration.getAuthorityID());
        } catch (ConfigurationException cfgEx) {
            logger.log(Level.SEVERE, "Cannot get issuer details from configuration", cfgEx);
        }

        return responseIssuer;

    }

    private Status newStatus(Throwable th) {

        Status status = SAML2ObjectBuilder.buildStatus();

        if (th.getMessage() != null) {
            StatusMessage statusMessage = SAML2ObjectBuilder.buildStatusMessage();
            statusMessage.setMessage(th.getMessage());
            status.setStatusMessage(statusMessage);
        }

        StatusCode statusCode = SAML2ObjectBuilder.buildStatusCode();

        if (th instanceof CodedException) {
            CodedException handlerEx = (CodedException) th;
            statusCode.setValue(handlerEx.getStatusCode());

            String subCode = handlerEx.getSubStatusCode();
            if (subCode != null) {
                StatusCode subStatusCode = SAML2ObjectBuilder.buildStatusCode();
                subStatusCode.setValue(subCode);
                statusCode.setStatusCode(subStatusCode);
            }

        } else {
            statusCode.setValue(StatusCode.RESPONDER_URI);
        }

        status.setStatusCode(statusCode);

        return status;

    }

    private void verifySignature(Signature signature, Subject requester)
        throws SecurityException, ConfigurationException, ValidationException {

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        X509Certificate subjectCertificate = null;
        Set<X509Certificate[]> allChain = requester.getPublicCredentials(X509Certificate[].class);
        for (X509Certificate[] peerChain : allChain) {
            subjectCertificate = peerChain[0];
        }
        if (subjectCertificate == null) {
            /*
             * TODO get the certificate from <KeyInfo/> even if is not mandatory for SAML XMLSig profile certificate
             * requires validation
             */
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        SignatureValidator signatureValidator = new SignatureValidator(peerCredential);
        signatureValidator.validate(signature);
        logger.fine("Signature verified for " + subjectCertificate.getSubjectX500Principal().getName());

    }

}
