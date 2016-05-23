package it.infn.security.saml.ocp;

import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManagerException;

import java.util.Date;

public class SPIDAttributeValue
    implements AttributeValueInterface {

    public static final String SPID_STRING_TYPE = "xs:string";

    public static final String SPID_DATE_TYPE = "xs:date";

    private Object value;

    private String type;

    private String description;

    public SPIDAttributeValue(String value, String type, String descr) throws SchemaManagerException {

        if (SPID_STRING_TYPE.equals(type)) {
            this.value = value;
            this.type = type;
            this.description = descr;
        } else if (SPID_DATE_TYPE.equals(type)) {
            /*
             * TODO parse date
             */
            this.type = type;
            this.description = descr;
        } else {
            throw new SchemaManagerException("Cannot identify value format");
        }
    }

    public SPIDAttributeValue(String value, String descr) {
        this.value = value;
        this.type = SPID_STRING_TYPE;
        this.description = descr;
    }

    public SPIDAttributeValue(Date value, String descr) {
        this.value = value;
        this.type = SPID_DATE_TYPE;
        this.description = descr;
    }

    public String getId() {
        /*
         * with SPID the ID of the value IS the value itself or a representation of it
         */
        if (type.equals(SPID_STRING_TYPE)) {

            return (String) value;

        } else if (type.equals(SPID_DATE_TYPE)) {

            return Long.toString(((Date) value).getTime());

        }

        return null;
    }

    public String getType() {
        return type;
    }

    public Object getValue() {
        return value;
    }

    public String encode(String format)
        throws SchemaManagerException {

        if (type.equals(SPID_STRING_TYPE)) {

            return (String) value;

        } else if (type.equals(SPID_DATE_TYPE)) {

            /*
             * TODO verify encoding
             */
            return Long.toString(((Date) value).getTime());

        }

        return null;
    }

    public String getDescription() {
        return description;
    }

}