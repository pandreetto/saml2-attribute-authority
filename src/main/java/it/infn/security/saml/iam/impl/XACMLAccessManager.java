package it.infn.security.saml.iam.impl;

import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;

import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClient;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.policy.ObligationsType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;

public class XACMLAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(XACMLAccessManager.class.getName());

    public static final String XACML_SAML_PROFILE_URI = "urn:mace:switch.ch:doc:xacml-saml:profile:200711:SOAP";

    private SAMLObjectBuilder<XACMLAuthzDecisionQueryType> authzDecisionQueryBuilder;

    private SOAPObjectBuilder<Body> bodyBuilder;

    private SOAPObjectBuilder<Envelope> envelopeBuilder;

    private SAMLObjectBuilder<Issuer> issuerBuilder;

    private SOAPClient soapClient;

    private String[] pdpEndpoints;

    private String messageIssuerId;

    public int getLoadPriority() {
        return 0;
    }

    @SuppressWarnings("unchecked")
    public void init()
        throws AccessManagerException {

        try {

            XMLObjectBuilderFactory objFactory = Configuration.getBuilderFactory();

            Object tmpo = objFactory.getBuilder(XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);
            authzDecisionQueryBuilder = (SAMLObjectBuilder<XACMLAuthzDecisionQueryType>) tmpo;
            bodyBuilder = (SOAPObjectBuilder<Body>) objFactory.getBuilder(Body.TYPE_NAME);
            envelopeBuilder = (SOAPObjectBuilder<Envelope>) objFactory.getBuilder(Envelope.TYPE_NAME);
            issuerBuilder = (SAMLObjectBuilder<Issuer>) objFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage());
        }
    }

    public void close()
        throws AccessManagerException {

    }

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    private SOAPClient buildSOAPClient(X509KeyManager keyManager, X509TrustManager trustManager, int conTimeout,
            int maxRequests, int buffSize) {

        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");
        httpClientBuilder.setConnectionTimeout(conTimeout);
        httpClientBuilder.setMaxTotalConnections(maxRequests);
        httpClientBuilder.setMaxConnectionsPerHost(maxRequests);
        httpClientBuilder.setReceiveBufferSize(buffSize);
        httpClientBuilder.setSendBufferSize(buffSize);

        if (keyManager != null && trustManager != null) {
            TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(httpClientBuilder.getMaxTotalConnections());
        return new HttpSOAPClient(httpClientBuilder.buildClient(), parserPool);

    }

    private ObligationsType processRequest(RequestType xacmlRequest)
        throws SOAPException, SecurityException, AccessManagerException {

        String samlRequestID = "_" + UUID.randomUUID().toString();

        SOAPMessageContext msgContext = new BasicSOAPMessageContext();
        msgContext.setCommunicationProfileId(XACML_SAML_PROFILE_URI);
        msgContext.setOutboundMessageIssuer(messageIssuerId);
        msgContext.setSOAPRequestParameters(new HttpSOAPRequestParameters(
                "http://www.oasis-open.org/committees/security"));

        XACMLAuthzDecisionQueryType samlRequest = authzDecisionQueryBuilder
                .buildObject(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20,
                        XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);
        samlRequest.setRequest(xacmlRequest);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(messageIssuerId);
        samlRequest.setIssuer(issuer);

        samlRequest.setID(samlRequestID);
        samlRequest.setIssueInstant(new DateTime());

        samlRequest.setInputContextOnly(false);
        samlRequest.setReturnContext(true);

        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlRequest);

        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        msgContext.setOutboundMessage(envelope);

        for (String pdpEp : pdpEndpoints) {

            soapClient.send(pdpEp, msgContext);

            Envelope soapResponse = (Envelope) msgContext.getInboundMessage();
            Response samlResponse = (Response) soapResponse.getBody().getOrderedChildren().get(0);

            if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
                logger.warning("Response from PDP " + pdpEp + " does not contain any assertion");
                continue;
            }
            if (samlResponse.getAssertions().size() > 1) {
                logger.warning("Response from PDP " + pdpEp + " contains more than 1 assertion");
                continue;
            }

            Assertion samlAssertion = samlResponse.getAssertions().get(0);

            List<Statement> authzStatements = samlAssertion
                    .getStatements(XACMLAuthzDecisionStatementType.TYPE_NAME_XACML20);
            if (authzStatements == null || authzStatements.isEmpty()) {
                logger.warning("Response from PDP " + pdpEp + " does not contain any authorization statement");
                continue;
            }
            if (authzStatements.size() > 1) {
                logger.warning("Response from PDP " + pdpEp + " contains more than 1 authorization statement");
                continue;
            }

            XACMLAuthzDecisionStatementType authzStatement = (XACMLAuthzDecisionStatementType) authzStatements.get(0);
            ResponseType xacmlResponse = authzStatement.getResponse();
            ResultType xacmlResult = xacmlResponse.getResult();

            switch (xacmlResult.getDecision().getDecision()) {
            case Deny:
                throw new AccessManagerException("Authorization denied for request " + samlRequestID);
            case Indeterminate:
                throw new AccessManagerException("Authorization indeterminated for request " + samlRequestID);
            case NotApplicable:
                throw new AccessManagerException("Authorization not applicable for request " + samlRequestID);
            case Permit:
                logger.info("Authorized request " + samlRequestID);
            }

            return xacmlResult.getObligations();
        }

        throw new AccessManagerException("Authorization failed: no response from PDPs");

    }

}
