
import {pki, forge} from 'node-forge';
import { jwt } from 'jsonwebtoken'

const PUBLIC_CERTIFICATE_BEGIN_HEADER = '-----BEGIN CERTIFICATE-----'
const PUBLIC_CERTIFICATE_END_HEADER = '-----END CERTIFICATE-----'

const verifyCertificateWithChain = ((derCertStr : string, caCerts : any) => {

    const derCert = `${PUBLIC_CERTIFICATE_BEGIN_HEADER}\n${derCertStr}\n${PUBLIC_CERTIFICATE_END_HEADER}`;
    const pemCert : pki.Certificate = pki.certificateFromPem(derCert);

    //ca certs to be an array with each cert having the same format
    // `${PUBLIC_CERTIFICATE_BEGIN_HEADER}\n${certificate}\n${PUBLIC_CERTIFICATE_END_HEADER}`;
    const caStore = pki.createCaStore(caCerts);

    return pki.verifyCertificateChain(caStore, [pemCert]);
})


const getPemFromDer = (str : string) => {
    str = str.replace(PUBLIC_CERTIFICATE_BEGIN_HEADER,'').replace(PUBLIC_CERTIFICATE_END_HEADER,'');
    const certAsn = forge.asn1.fromDer(forge.util.decode64(str));
    const cert = forge.pki.certificateFromAsn1(certAsn);
    const pemCert = forge.pki.publicKeyToPem(cert.publicKey);

    return pemCert;

} 

const verifyJwt = (jwtToken : string, derCert: string) => {
    return jwt.verify(jwtToken, getPemFromDer(derCert), { algorithms : ['RS256']});
}