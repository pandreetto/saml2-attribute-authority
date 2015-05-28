package it.infn.security.saml.aa;

import org.opensaml.saml2.core.StatusCode;

public class CodedException extends Exception{
    
    public static final long serialVersionUID = 1432737173;
    
    protected String code;
    
    protected String subcode;
    
    public CodedException(String msg, String code, String subcode) {
        super(msg);
        this.code = code;
        this.subcode = subcode;
    }

    public CodedException(String msg, String code) {
        this(msg, code, (String) null);
    }

    public CodedException(String msg) {
        this(msg, StatusCode.RESPONDER_URI, (String) null);
    }

    public CodedException(String msg, String code, String subcode, Throwable th) {
        super(msg, th);
        this.code = code;
        this.subcode = subcode;
    }

    public CodedException(String msg, String code, Throwable th) {
        this(msg, code, (String) null, th);
    }

    public CodedException(String msg, Throwable th) {
        this(msg, StatusCode.RESPONDER_URI, (String) null, th);
    }

    public String getStatusCode() {
        return code;
    }

    public String getSubStatusCode() {
        return subcode;
    }

}