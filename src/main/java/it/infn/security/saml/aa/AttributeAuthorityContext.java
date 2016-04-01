package it.infn.security.saml.aa;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.opensaml.xml.XMLObject;

public class AttributeAuthorityContext {

    private static ThreadLocal<HttpServletRequest> request = new ThreadLocal<HttpServletRequest>();

    private static ThreadLocal<XMLObject> payload = new ThreadLocal<XMLObject>();

    public static void init(HttpServletRequest req, XMLObject parsedPayload) {
        request.set(req);
        payload.set(parsedPayload);
    }

    public static HttpServletRequest getRequest() {

        HttpServletRequest result = request.get();
        if (result != null) {
            return result;
        }

        /*
         * Back compatibility with the JAX-WS implementation of the service
         */
        Message currMsg = PhaseInterceptorChain.getCurrentMessage();
        if (currMsg != null) {
            return (HttpServletRequest) currMsg.get("HTTP.REQUEST");
        }

        return null;
    }

    public static XMLObject getPayload() {
        return payload.get();
    }

    public static void release() {
        request.remove();
        payload.remove();
    }
}