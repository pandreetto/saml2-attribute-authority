package it.infn.security.saml.utils;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.ContentReference;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SignUtils {

    private static final Logger logger = Logger.getLogger(SignUtils.class.getName());

    private static final Base64 base64Enc = new Base64(64, new byte[] { '\n' });

    public static KeyInfo buildKeyInfo(X509Certificate signCert)
        throws CertificateException {

        KeyInfo keyInfo = SAML2ObjectBuilder.buildKeyInfo();
        KeyName keyName = SAML2ObjectBuilder.buildKeyName();
        X509Data x509Data = SAML2ObjectBuilder.buildX509Data();
        X509SubjectName x509Sbj = SAML2ObjectBuilder.buildX509SubjectName();

        org.opensaml.xml.signature.X509Certificate x509Cert = SAML2ObjectBuilder.buildX509Certificate();
        keyName.setValue(signCert.getSubjectDN().getName());
        x509Sbj.setValue(signCert.getSubjectDN().getName());
        x509Data.getX509SubjectNames().add(x509Sbj);
        byte[] certEncoded = signCert.getEncoded();
        x509Cert.setValue(base64Enc.encodeToString(certEncoded));
        x509Data.getX509Certificates().add(x509Cert);

        keyInfo.getKeyNames().add(keyName);
        keyInfo.getX509Datas().add(x509Data);

        return keyInfo;
    }

    private static void validateCertificateChain(X509Certificate[] certChain)
        throws CertificateException {
        try {
            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

            X509TrustManager trustMan = configuration.getTrustManager();
            trustMan.checkClientTrusted(certChain, "RSA");

        } catch (CertificateException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new CertificateException(ex.getMessage());
        }
    }

    public static X509Certificate[] extractCertificateChain(Signature signature)
        throws CertificateException {

        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            return null;
        }

        List<X509Data> x509Datas = keyInfo.getX509Datas();
        if (x509Datas == null || x509Datas.size() == 0) {
            return null;
        }

        for (X509Data tmpData : x509Datas) {

            List<org.opensaml.xml.signature.X509Certificate> tmpCerts = tmpData.getX509Certificates();
            if (tmpCerts != null && tmpCerts.size() > 0) {
                X509Certificate[] result = new X509Certificate[tmpCerts.size()];

                for (int idx = 0; idx < tmpCerts.size(); idx++) {
                    String b64cert = tmpCerts.get(idx).getValue();
                    ByteArrayInputStream bIn = new ByteArrayInputStream(Base64.decodeBase64(b64cert));
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    result[idx] = (X509Certificate) cf.generateCertificate(bIn);
                }

                /*
                 * use the first x509Data element with certificates
                 */
                return result;
            }

        }

        return null;
    }

    public static void signObject(SignableXMLObject object, String signAlgorithm, String digestAlgorithm)
        throws ConfigurationException, SchemaManagerException, SignatureException, MarshallingException,
        CertificateException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        SchemaManager schemaManager = SchemaManagerFactory.getManager();

        X509Certificate srvCert = configuration.getServiceCertificate();
        PrivateKey srvKey = configuration.getServicePrivateKey();
        Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

        if (signAlgorithm == null || signAlgorithm.length() == 0) {
            signAlgorithm = configuration.getSignatureAlgorithm();
        }
        schemaManager.checkSignatureAlgorithm(signAlgorithm);

        Signature objSignature = SAML2ObjectBuilder.buildSignature();
        objSignature.setSigningCredential(credential);
        objSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        objSignature.setSignatureAlgorithm(signAlgorithm);
        objSignature.setKeyInfo(SignUtils.buildKeyInfo(srvCert));

        object.setSignature(objSignature);

        if (digestAlgorithm == null || digestAlgorithm.length() == 0) {
            digestAlgorithm = configuration.getDigestAlgorithm();
        }
        schemaManager.checkDigestAlgorithm(digestAlgorithm);

        for (ContentReference refItem : objSignature.getContentReferences()) {
            if (refItem instanceof SAMLObjectContentReference) {
                ((SAMLObjectContentReference) refItem).setDigestAlgorithm(digestAlgorithm);
            }
        }

        Marshaller marshaller = SAML2ObjectBuilder.getMarshaller(object);
        marshaller.marshall(object);

        Signer.signObject(objSignature);
    }

    public static void signObject(SignableXMLObject object)
        throws ConfigurationException, SchemaManagerException, SignatureException, MarshallingException,
        CertificateException {
        signObject(object, null, null);
    }

    public static void verifySignature(Signature signature, Subject requester)
        throws SecurityException, SchemaManagerException, ConfigurationException, CertificateException,
        ValidationException {

        SchemaManager schemaManager = SchemaManagerFactory.getManager();
        schemaManager.checkSignatureAlgorithm(signature.getSignatureAlgorithm());
        /*
         * TODO check digest algorithm
         */
        //schemaManager.checkDigestAlgorithm(extractDigestAlgorithm(signature));

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        X509Certificate subjectCertificate = null;

        X509Certificate[] peerChain = extractCertificateChain(signature);
        if (peerChain != null && peerChain.length > 0) {
            validateCertificateChain(peerChain);
            subjectCertificate = peerChain[0];
        }

        if (subjectCertificate == null) {
            Set<X509Certificate[]> allChain = requester.getPublicCredentials(X509Certificate[].class);
            for (X509Certificate[] chain : allChain) {
                subjectCertificate = chain[0];
                break;
            }
        }

        if (subjectCertificate == null) {
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        SignatureValidator signatureValidator = new SignatureValidator(peerCredential);
        signatureValidator.validate(signature);
        logger.fine("Signature verified for " + subjectCertificate.getSubjectX500Principal().getName());

    }

    public static String extractDigestAlgorithm(Signature signature) {

        Element signElem = signature.getDOM();

        if (signElem == null)
            return null;

        NodeList tmpl1 = signElem.getElementsByTagName("SignedInfo");
        if (tmpl1 != null && tmpl1.getLength() > 0) {
            NodeList tmpl2 = ((Element) tmpl1.item(0)).getElementsByTagName("Reference");
            if (tmpl2 != null && tmpl2.getLength() > 0) {
                NodeList tmpl3 = ((Element) tmpl2.item(0)).getElementsByTagName("DigestMethod");
                if (tmpl3 != null && tmpl3.getLength() > 0) {
                    String result = ((Element) tmpl3.item(0)).getAttribute("Algorithm");
                    return result;
                }
            }
        }

        return null;
    }

}