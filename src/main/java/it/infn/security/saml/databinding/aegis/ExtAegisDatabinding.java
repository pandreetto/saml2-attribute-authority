package it.infn.security.saml.databinding.aegis;

import org.apache.cxf.aegis.AegisContext;
import org.apache.cxf.aegis.databinding.AegisDatabinding;
import org.apache.cxf.aegis.type.TypeMapping;
import org.opensaml.DefaultBootstrap;

public class ExtAegisDatabinding
    extends AegisDatabinding {

    public ExtAegisDatabinding() {
        super();

        try {
            DefaultBootstrap.bootstrap();

            AegisContext aegisCtx = this.getAegisContext();
            TypeMapping tMap = aegisCtx.getTypeMapping();

            tMap.register(new AttributeQueryType());
            tMap.register(new ResponseType());

        } catch (Throwable th) {
            /*
             * TODO log exception
             */
        }

    }

}
