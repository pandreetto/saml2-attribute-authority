package it.infn.security.saml.iam;

import it.infn.security.saml.aa.CodedException;

public class IdentityManagerException
    extends CodedException {

    public static final long serialVersionUID = 1432299159;

    public IdentityManagerException(String msg, String code, String subcode) {
        super(msg, code, subcode);
    }

    public IdentityManagerException(String msg, String code) {
        super(msg, code);
    }

    public IdentityManagerException(String msg) {
        super(msg);
    }

    public IdentityManagerException(String msg, String code, String subcode, Throwable th) {
        super(msg, code, subcode, th);
    }

    public IdentityManagerException(String msg, String code, Throwable th) {
        super(msg, code, th);
    }

    public IdentityManagerException(String msg, Throwable th) {
        super(msg, th);
    }

}