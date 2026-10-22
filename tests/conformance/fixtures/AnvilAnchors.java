import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Base64;
import java.util.ArrayList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;

/** Freeze the pinned suite's default chain; never install its issuer system-wide. */
public class AnvilAnchors {
    private static byte[] encode(X509CertificateConfig config) throws Exception {
        var cert = new X509Certificate("fixture", config);
        cert.getPreparator(new X509Context(config).getChooser()).prepare();
        var der = new java.io.ByteArrayOutputStream();
        der.write(cert.getTagOctets().getValue());
        der.write(cert.getLengthOctets().getValue());
        der.write(cert.getContent().getValue());
        return der.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        var tls = Config.createConfig();
        var chain = new ArrayList<CertificateBytes>();
        for (var cert : tls.getCertificateChainConfig()) {
            cert.setNotBefore(DateTime.parse("2026-01-01T00:00:00Z"));
            cert.setNotAfter(DateTime.parse("2028-01-01T00:00:00Z"));
            cert.setSelfSigned(chain.size() > 0);
            chain.add(new CertificateBytes(encode(cert)));
        }
        // Joda DateTime values serialize as empty XML elements in this pin.
        // Explicit DER retains controlled validity through the config round trip.
        tls.setDefaultExplicitCertificateChain(chain);
        tls.setAutoAdjustCertificate(false);
        Files.writeString(Path.of(args[0]), "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(chain.get(1).getBytes())
                + "\n-----END CERTIFICATE-----\n");
        ConfigIO.write(tls, Path.of(args[1]).toFile());
    }
}
