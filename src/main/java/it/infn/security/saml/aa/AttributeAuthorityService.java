package it.infn.security.saml.aa;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.ParameterStyle;
import javax.jws.soap.SOAPBinding.Style;
import javax.jws.soap.SOAPBinding.Use;

import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;

@WebService(name = "SAMLTest", targetNamespace = "http://saml.security.infn.it")
public interface AttributeAuthorityService {

    @WebMethod(operationName = "AttributeQuery")
    @SOAPBinding(style = Style.DOCUMENT, use = Use.LITERAL, parameterStyle = ParameterStyle.BARE)
    public @WebResult(name = "Response", targetNamespace = "urn:oasis:names:tc:SAML:2.0:protocol")
    Response process(@WebParam(targetNamespace = "urn:oasis:names:tc:SAML:2.0:protocol")
    AttributeQuery arg1);

}
