package it.infn.security.saml.aa;

import it.infn.security.saml.aa.impl.AttributeAuthorityServiceImpl;
import it.infn.security.saml.utils.SAML2ObjectBuilder;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.FaultCode;
import org.opensaml.ws.soap.soap11.FaultString;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.XMLHelper;

public class AttributeAuthorityServlet
    extends HttpServlet {

    private static final long serialVersionUID = 1448629690;

    private static final Logger logger = Logger.getLogger(AttributeAuthorityServlet.class.getName());

    private static ThreadLocal<HttpServletRequest> servletRequest = new ThreadLocal<HttpServletRequest>();

    private HTTPSOAP11Encoder messageEncoder;

    private HTTPSOAP11Decoder messageDecoder;

    private AttributeAuthorityService service;

    public void init(ServletConfig config)
        throws ServletException {

        super.init(config);

        messageDecoder = new HTTPSOAP11Decoder();
        messageEncoder = new HTTPSOAP11Encoder();
        service = new AttributeAuthorityServiceImpl();

    }

    public void doPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {

        servletRequest.set(httpRequest);

        AAMessageContext messageContext = new AAMessageContext();
        HttpServletRequestAdapter reqAdapter = new HttpServletRequestAdapter(httpRequest);
        HttpServletResponseAdapter resAdapter = new HttpServletResponseAdapter(httpResponse, httpRequest.isSecure());

        messageContext.setInboundMessageTransport(reqAdapter);
        messageContext.setOutboundMessageTransport(resAdapter);
        /*
         * TODO messageContext.setSecurityPolicyResolver(resolver)
         */

        try {

            if (logger.isLoggable(Level.FINE)) {
                String tmps = XMLHelper.prettyPrintXML(messageContext.getOutboundMessage().getDOM());
                logger.fine("SOAP request:\n" + tmps);
            }

            messageDecoder.decode(messageContext);

            AttributeQuery request = messageContext.getInboundSAMLMessage();
            Response response = service.attributeQuery(request);

            messageContext.setOutboundSAMLMessage(response);
            messageContext.setOutboundSAMLMessageIssueInstant(response.getIssueInstant());
            messageContext.setOutboundMessageIssuer(response.getIssuer().getValue());
            messageContext.setOutboundSAMLMessageId(response.getID());

            messageEncoder.encode(messageContext);

        } catch (SecurityException secEx) {

            if (logger.isLoggable(Level.FINE)) {
                logger.log(Level.SEVERE, secEx.getMessage(), secEx);
            } else {
                logger.log(Level.SEVERE, secEx.getMessage());
            }
            buildSOAPFault(messageContext, secEx);

        } catch (MessageEncodingException msgEx) {
            if (logger.isLoggable(Level.FINE)) {
                logger.log(Level.SEVERE, msgEx.getMessage(), msgEx);
            } else {
                logger.log(Level.SEVERE, msgEx.getMessage());
            }
        } catch (MessageDecodingException msgEx) {
            buildSOAPFault(messageContext, msgEx);
        } finally {
            servletRequest.remove();
        }

    }

    public void doDelete(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public void doHead(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public void doOptions(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public void doPut(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public void doTrace(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    public static HttpServletRequest getCurrentRequest() {
        return servletRequest.get();
    }

    private String getSupportedMethods() {
        return "POST";
    }

    public class AAMessageContext
        extends BasicSAMLMessageContext<AttributeQuery, Response, NameID> {

    }

    private Envelope buildSOAPFault(AAMessageContext messageContext, Exception ex) {

        HTTPOutTransport outTransport = (HTTPOutTransport) messageContext.getOutboundMessageTransport();
        outTransport.setStatusCode(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        Fault fault = SAML2ObjectBuilder.buildFault();

        FaultCode faultCode = SAML2ObjectBuilder.buildFaultCode();
        faultCode.setValue(FaultCode.CLIENT);
        fault.setCode(faultCode);

        FaultString faultString = SAML2ObjectBuilder.buildFaultString();

        StringBuilder sb = new StringBuilder();
        sb.append(ex.getMessage());
        Throwable cause = ex.getCause();
        while (cause != null) {
            sb.append(": ").append(cause.getMessage());
            cause = cause.getCause();
        }

        faultString.setValue(sb.toString());
        fault.setMessage(faultString);

        Envelope envelope = SAML2ObjectBuilder.buildEnvelope();

        Body body = SAML2ObjectBuilder.buildBody();
        body.getUnknownXMLObjects().add(fault);
        envelope.setBody(body);
        return envelope;

    }

}