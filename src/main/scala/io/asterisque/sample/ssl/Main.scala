package io.asterisque.sample.ssl

import java.io.FileInputStream
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, Principal, PrivateKey, Security}
import java.text.SimpleDateFormat

import javax.net.ssl._
import org.slf4j.LoggerFactory

import scala.collection.JavaConverters._
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

object Main {
  private[this] val logger = LoggerFactory.getLogger(getClass.getName.dropRight(1))

  def main(args: Array[String]): Unit = {
    logger.info("[Algorithms]")
    logger.info(s"KeyFactory: ${Security.getAlgorithms("KeyFactory").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"CertificateFactory: ${Security.getAlgorithms("CertificateFactory").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"SSLContext: ${Security.getAlgorithms("SSLContext").asScala.toSeq.sorted.mkString(", ")}")

    val caKey = loadPrivateKey(Paths.get("cert", "cakey.pk8"))
    val caCert = loadCertificate(Paths.get("cert", "cacert.pem"))

    val serverKey = loadPrivateKey(Paths.get("cert", "serverkey.pk8"))
    val serverCert = loadCertificate(Paths.get("cert", "servercert.pem"))
    val server = new Server(serverKey, serverCert, caCert)
    val port = server.listen()

    val clientKey = loadPrivateKey(Paths.get("cert", "clientkey.pk8"))
    val clientCert = loadCertificate(Paths.get("cert", "clientcert.pem"))
    val client = new Client(clientKey, clientCert, caCert)
    client.connect(port)
  }

  class Server(key: PrivateKey, cert: X509Certificate, trust: X509Certificate) {
    def listen(): Int = {
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(Array(new SimpleKeyManager("SERVER", key, cert)), Array(new SimpleTrustManager("SERVER", trust)), null)
      val factory = sslContext.getServerSocketFactory
      val serverSocket = factory.createServerSocket(0).asInstanceOf[SSLServerSocket]
      serverSocket.setNeedClientAuth(true)
      val port = serverSocket.getLocalPort
      Future {
        val socket = serverSocket.accept()
        serverSocket.close()
        serve(socket.asInstanceOf[SSLSocket])
      }
      port
    }

    private[this] def serve(socket: SSLSocket): Unit = {
      dump("SERVER", socket)
      val in = socket.getInputStream
      val data = Iterator.continually(in.read()).takeWhile(_ != '\n').map(_.toByte).toArray :+ '\n'.toByte
      val out = socket.getOutputStream
      out.write(data)
      out.flush()
      socket.close()
    }
  }

  class Client(key: PrivateKey, cert: X509Certificate, trust: X509Certificate) {
    def connect(port: Int): Unit = {
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(Array(new SimpleKeyManager("CLIENT", key, cert)), Array(new SimpleTrustManager("CLIENT", trust)), null)
      val factory = sslContext.getSocketFactory
      val clientSocket = factory.createSocket("localhost", port).asInstanceOf[SSLSocket]
      dump("CLIENT", clientSocket)
      val out = clientSocket.getOutputStream
      out.write("hello, world\n".getBytes(StandardCharsets.UTF_8))
      logger.info("CLIENT >> \"hello, world\\n\"")
      out.flush()
      val in = clientSocket.getInputStream
      val data = new String(Iterator.continually(in.read()).takeWhile(_ >= 0).map(_.toByte).toArray, StandardCharsets.UTF_8)
      logger.info(s"CLIENT << $data")
      clientSocket.close()
    }
  }

  class SimpleKeyManager(prefix: String, key: PrivateKey, cert: X509Certificate) extends X509ExtendedKeyManager {
    override def getClientAliases(keyType: String, issuers: Array[Principal]): Array[String] = {
      logger.debug(s"$prefix: getClientAliases($keyType, ${str(issuers)})")
      Array.empty
    }

    override def chooseClientAlias(keyType: Array[String], issuers: Array[Principal], socket: Socket): String = {
      logger.debug(s"$prefix: chooseClientAlias(${str(keyType)}, ${str(issuers)}, $socket)")
      "alias"
    }

    override def getServerAliases(keyType: String, issuers: Array[Principal]): Array[String] = {
      logger.debug(s"$prefix: getServerAliases($keyType, ${str(issuers)})")
      Array.empty
    }

    override def chooseServerAlias(keyType: String, issuers: Array[Principal], socket: Socket): String = {
      logger.debug(s"$prefix: chooseServerAlias($keyType, ${str(issuers)}, $socket)")
      "alias"
    }

    override def getCertificateChain(alias: String): Array[X509Certificate] = {
      logger.debug(s"$prefix: getCertificateChain($alias)")
      Array(cert)
    }

    override def getPrivateKey(alias: String): PrivateKey = {
      logger.debug(s"$prefix: getPrivateKey($alias)")
      key
    }
  }

  class SimpleTrustManager(prefix: String, trust: X509Certificate) extends X509ExtendedTrustManager {
    override def checkClientTrusted(chain: Array[X509Certificate], authType: String, socket: Socket): Unit = {
      logger.debug(s"$prefix: checkClientTrusted(${str(chain)}, $authType, $socket)")
    }

    override def checkServerTrusted(chain: Array[X509Certificate], authType: String, socket: Socket): Unit = {
      logger.debug(s"$prefix: checkServerTrusted(${str(chain)}, $authType, $socket)")
    }

    override def checkClientTrusted(chain: Array[X509Certificate], authType: String, sslEngine: SSLEngine): Unit = {
      logger.debug(s"$prefix: checkClientTrusted(${str(chain)}, $authType, $sslEngine)")
    }

    override def checkServerTrusted(chain: Array[X509Certificate], authType: String, sslEngine: SSLEngine): Unit = {
      logger.debug(s"$prefix: checkServerTrusted(${str(chain)}, $authType, $sslEngine)")
    }

    override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = {
      logger.debug(s"$prefix: checkClientTrusted(${str(chain)}, $authType)")
    }

    override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = {
      logger.debug(s"$prefix: checkServerTrusted(${str(chain)}, $authType)")
    }

    override def getAcceptedIssuers: Array[X509Certificate] = {
      logger.debug(s"$prefix: getAcceptedIssuers()")
      Array(trust)
    }
  }

  private[this] def loadCertificate(file: Path): X509Certificate = {
    val certFactory = CertificateFactory.getInstance("X.509")
    using(new FileInputStream(file.toFile)) { in =>
      certFactory.generateCertificate(in).asInstanceOf[X509Certificate]
    }
  }

  private[this] def loadPrivateKey(file: Path): PrivateKey = {
    val keyFactory = KeyFactory.getInstance("EC")
    val keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(file))
    keyFactory.generatePrivate(keySpec)
  }

  private[this] def using[R <: AutoCloseable, T](resource: R)(f: R => T): T = try {
    f(resource)
  } finally {
    resource.close()
  }

  private[this] def dump(prefix: String, socket: SSLSocket): Unit = {

    val df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
    socket.getSession // force handshake
    logger.info(s"$prefix: Enabled Cipher Suites: ${str(socket.getEnabledCipherSuites)}")
    logger.info(s"$prefix: Enable Protocols: ${str(socket.getEnabledProtocols)}")
    logger.info(s"$prefix: Enable Session Creation: ${socket.getEnableSessionCreation}")
    logger.info(s"$prefix: Need Client Auth: ${socket.getNeedClientAuth}")
    logger.info(s"$prefix: Supported Cipher Suites: ${str(socket.getSupportedCipherSuites)}")
    logger.info(s"$prefix: Supported Protocols: ${str(socket.getSupportedProtocols)}")
    logger.info(s"$prefix: Use Client Mode: ${socket.getUseClientMode}")
    logger.info(s"$prefix: Want Client Auth: ${socket.getWantClientAuth}")
    logger.info(s"$prefix: SSL Session:")
    logger.info(s"$prefix:   ID: ${socket.getSession.getId.map(x => f"$x%02X").mkString}")
    logger.info(s"$prefix:   Cipher Suite: ${socket.getSession.getCipherSuite}")
    logger.info(s"$prefix:   Creation Time: ${df.format(socket.getSession.getCreationTime)}")
    logger.info(s"$prefix:   Last Access Time: ${df.format(socket.getSession.getLastAccessedTime)}")
    logger.info(s"$prefix:   Local Principal: ${socket.getSession.getLocalPrincipal.getName}")
    logger.info(s"$prefix:   Local Certificates: ${str(socket.getSession.getLocalCertificates)}")
    logger.info(s"$prefix:   Peer Principal: ${socket.getSession.getPeerPrincipal.getName}")
    logger.info(s"$prefix:   Peer Certificates: ${str(socket.getSession.getPeerCertificates)}")
  }

  private def str[T](arr: Array[T]): String = if (arr == null) "null" else arr.map {
    case s: String => s
    case cert: X509Certificate => cert.getSubjectX500Principal.getName
    case obj => obj.toString
  }.mkString("[", ", ", "]")
}
