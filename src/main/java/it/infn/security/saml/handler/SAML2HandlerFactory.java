package it.infn.security.saml.handler;

public class SAML2HandlerFactory {
    
    public static SAML2Handler getHandler() {
        return new it.infn.security.saml.ocp.OCPSAML2Handler();
    }
    
}