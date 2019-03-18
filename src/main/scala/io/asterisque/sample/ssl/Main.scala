package io.asterisque.sample.ssl

import java.io.FileInputStream
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.{Path, Paths}
import java.security._
import java.security.cert.{Certificate, _}
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
    logger.info(s"KeyManagerFactory: ${Security.getAlgorithms("KeyManagerFactory").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"KeyStore: ${Security.getAlgorithms("KeyStore").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"CertificateFactory: ${Security.getAlgorithms("CertificateFactory").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"SSLContext: ${Security.getAlgorithms("SSLContext").asScala.toSeq.sorted.mkString(", ")}")
    logger.info(s"TrustManagerFactory: ${Security.getAlgorithms("TrustManagerFactory").asScala.toSeq.sorted.mkString(", ")}")

    val caCert = loadCertificate(Paths.get("cert", "cacert.pem"))
    val caTrustManagerFactory = {
      val trustAnchor = new TrustAnchor(caCert, null)
      val certSelector = new CertSelector {
        override def `match`(cert: Certificate): Boolean = true
      }
      val params = new CertPathTrustManagerParameters(new PKIXBuilderParameters(Set(trustAnchor).asJava, certSelector))
      val tmf = TrustManagerFactory.getInstance("PKIX")
      tmf.init(params)
      tmf
    }

    val serverKeyManagerFactory = loadKeyManager(Paths.get("cert", "server.pk12"), "****")
    val server = new Server(serverKeyManagerFactory, caCert)
    val port = server.listen()

    val clientKeyManagerFactory = loadKeyManager(Paths.get("cert", "client.pk12"), "####")
    val client = new Client(clientKeyManagerFactory, caCert)
    client.connect(port)
  }

  class Server(keyManagerFactory: KeyManagerFactory, trust: X509Certificate) {
    def listen(): Int = {
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(keyManagerFactory.getKeyManagers, Array(new SimpleTrustManager("SERVER", trust)), null)
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

  class Client(keyManagerFactory: KeyManagerFactory, trust: X509Certificate) {
    def connect(port: Int): Unit = {
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(keyManagerFactory.getKeyManagers, Array(new SimpleTrustManager("CLIENT", trust)), null)
      val factory = sslContext.getSocketFactory
      val clientSocket = factory.createSocket("localhost", port).asInstanceOf[SSLSocket]
      dump("CLIENT", clientSocket)
      val out = clientSocket.getOutputStream
      val s = "hello, world\n"
      out.write(s.getBytes(StandardCharsets.UTF_8))
      logger.info(s"CLIENT >> ${str(s)}")
      out.flush()
      val in = clientSocket.getInputStream
      val data = new String(Iterator.continually(in.read()).takeWhile(_ >= 0).map(_.toByte).toArray, StandardCharsets.UTF_8)
      logger.info(s"CLIENT << ${str(data)}")
      clientSocket.close()
    }
  }

  private[this] class SimpleTrustManager(prefix: String, trust: X509Certificate) extends X509ExtendedTrustManager {
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

  private[this] def loadKeyManager(file: Path, password: String): KeyManagerFactory = {
    val keyStore = KeyStore.getInstance("PKCS12")
    using(new FileInputStream(file.toFile)) { in =>
      keyStore.load(in, password.toCharArray)
    }
    val keyManagerFactory = KeyManagerFactory.getInstance("SunX509")
    keyManagerFactory.init(keyStore, password.toCharArray)
    keyManagerFactory
  }


  private[this] def using[R <: AutoCloseable, T](resource: R)(f: R => T): T = try {
    f(resource)
  } finally {
    resource.close()
  }

  private[this] def dump(prefix: String, socket: SSLSocket): Unit = {

    val df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
    val session = socket.getSession // force handshake
    logger.synchronized {
      logger.info("-------------")
      logger.info(s"$prefix: Supported Cipher Suites: ${str(socket.getSupportedCipherSuites)}")
      logger.info(s"$prefix: Enabled   Cipher Suites: ${str(socket.getEnabledCipherSuites)}")
      logger.info(s"$prefix: Supported Protocols: ${str(socket.getSupportedProtocols)}")
      logger.info(s"$prefix: Enabled   Protocols: ${str(socket.getEnabledProtocols)}")
      logger.info(s"$prefix: Enable Session Creation: ${socket.getEnableSessionCreation}")
      logger.info(s"$prefix: Need Client Auth: ${socket.getNeedClientAuth}")
      logger.info(s"$prefix: Use Client Mode: ${socket.getUseClientMode}")
      logger.info(s"$prefix: Want Client Auth: ${socket.getWantClientAuth}")
      logger.info(s"$prefix: SSL Session:")
      logger.info(s"$prefix:   ID: ${session.getId.map(x => f"$x%02X").mkString}")
      logger.info(s"$prefix:   Protocol: ${session.getProtocol}")
      logger.info(s"$prefix:   Cipher Suite: ${session.getCipherSuite}")
      logger.info(s"$prefix:   Creation Time: ${df.format(session.getCreationTime)}")
      logger.info(s"$prefix:   Last Access Time: ${df.format(session.getLastAccessedTime)}")
      logger.info(s"$prefix:   Local Principal: ${Option(session.getLocalPrincipal).map(_.getName).orNull}")
      logger.info(s"$prefix:   Local Certificates: ${str(session.getLocalCertificates)}")
      logger.info(s"$prefix:   Peer Principal: ${Option(session.getPeerPrincipal).map(_.getName).orNull}")
      logger.info(s"$prefix:   Peer Certificates: ${str(session.getPeerCertificates)}")
      logger.info(s"$prefix:   Value Names: ${str(session.getValueNames)}")
    }
  }

  private def str[T](arr: Array[T]): String = if (arr == null) "null" else arr.map {
    case s: String => s
    case cert: X509Certificate => s"{${cert.getSubjectX500Principal.getName}"
    case obj => obj.toString
  }.mkString("[", ", ", "]")

  private def str(s: String): String = s.map {
    case '\n' => "\\n"
    case ch => ch.toString
  }.mkString("\"", "", "\"")
}
