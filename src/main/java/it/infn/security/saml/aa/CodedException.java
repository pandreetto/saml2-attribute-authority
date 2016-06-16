package it.infn.security.saml.aa;

public class CodedException
    extends Exception {

    public static final long serialVersionUID = 1432737173;

    public static final int BAD_REQUEST = 400;

    public static final int UNAUTHORIZED = 401;

    public static final int FORBIDDEN = 403;

    public static final int NOT_FOUND = 404;

    public static final int NOT_ACCEPTABLE = 406;

    public static final int CONFLICT = 409;

    public static final int SRV_ERROR = 500;

    public static final int BAD_VERSION = 600;

    protected int code;

    public CodedException(String msg, int code) {
        super(msg);
        this.code = code;
    }

    public CodedException(String msg) {
        this(msg, SRV_ERROR);
    }

    public CodedException(String msg, int code, Throwable th) {
        super(msg, th);
        this.code = code;
    }

    public CodedException(String msg, Throwable th) {
        this(msg, SRV_ERROR, th);
    }

    public int getCode() {
        return code;
    }

}