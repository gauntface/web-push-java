package com.ameyakarve.browserpushjava;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by akarve on 4/27/16.
 */
public abstract class BaseTestCase {
  final String publicKeyBase64 = "BOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY=";
  final BigInteger publicKeyX = new BigInteger("E83929F62205D0C3445D76462D7BCB7BFE3CE3EBF17D2754FDA30E3A303D523F", 16);
  final BigInteger publicKeyY = new BigInteger("0CC294D5A43738B74F1F589A6A4BD1F7F3C7ABAB4D0B3247DF9BFF254CF672B6", 16);

  final String privateKeyBase64 = "uDNsfsz91y2ywQeOHljVoiUg3j5RGrDVAswRqjP3v90=";
  final BigInteger privateKeyS = new BigInteger("B8336C7ECCFDD72DB2C1078E1E58D5A22520DE3E511AB0D502CC11AA33F7BFDD", 16);

  final String p256dh = "BCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn_-0yP7QQA=";

  final String _clientAuthUrlBase64 = "8eDyX_uCN0XRhSbY5hs7Hg==";

  final String expectedSharedSecret = "vgkL5otElJ7tB3jnxop9g7sGxuM4gGs5NL3qTCxe9JE="; //base64 shared secret

  final EllipticCurveKeyUtil _ellipticCurveKeyUtils;

  final KeyPair _serverKeyPair;
  final ECPublicKey _clientPublicKey;

  final String _exampleSalt = "AAAAAAAAAAAAAAAAAAAAAA==";

  final String messageToEncrypt = "Hello, World.";
  final String expectedEncryptedMessage = "CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==";

  final String bigMessageThatFails = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam et odio in sem ultrices feugiat ut at sem. Aliquam quis ex id leo rutrum dignissim et ut felis. Pellentesque fringilla tincidunt lorem at suscipit. Integer ut augue non tellus rhoncus pretium. Duis lacinia a mi vitae dictum. Ut dictum fermentum felis, a volutpat tellus tristique vel. Quisque ac tortor purus. Ut ullamcorper euismod maximus. Vivamus vel accumsan nisl.Mauris consectetur lectus odio, sed porttitor mauris viverra nec. Nam aliquam lacus in nisi tincidunt porta. Fusce maximus scelerisque neque non blandit. Suspendisse potenti. Praesent at magna sed eros mollis ultricies. Vestibulum posuere sagittis tellus nec feugiat. Ut ut sem sed augue sagittis ornare. Integer enim neque, lacinia a tristique a, commodo eget lacus. Nam elementum vulputate tortor, eu ornare eros iaculis eu.Cras luctus sem eget iaculis pharetra. Mauris vitae faucibus ex. Phasellus venenatis ante enim, a hendrerit libero vulputate ac. Vestibulum consequat ullamcorper dui sed pulvinar. Sed condimentum bibendum tellus, in pellentesque justo ultricies eget. Fusce bibendum eros at metus accumsan, vitae posuere nisl tempor. Donec sed tincidunt nunc, sagittis eleifend elit. Aenean rutrum et dui tincidunt tempus. Ut sollicitudin ac arcu eu molestie. Etiam ac mi cursus, hendrerit ex et, elementum felis. Donec vitae volutpat nibh, nec finibus ipsum. Nam nec commodo est, a viverra libero.Sed eu metus sapien. Nulla ac est pretium, pretium turpis eget, porttitor mauris. Praesent a dolor vel libero congue dictum ullamcorper sed massa. Sed eget justo justo. Curabitur elit velit, porta vitae facilisis a, vehicula eget mi. Fusce gravida ut libero nec malesuada. Sed ac cursus turpis, sodales porta diam. Maecenas eget mattis arcu. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Suspendisse eget urna tincidunt, rhoncus nisl sit amet, tincidunt diam. Donec condimentum turpis elit, eget condimentum sapien pulvinar sit amet. Sed ut dolor ut libero mollis luctus. Nullam vitae pretium lacus. Proin interdum congue risus, fermentum convallis dolor consectetur ac.Integer a lobortis lectus, eget interdum nisi. Sed vehicula sed velit non vestibulum. Aliquam egestas leo ac dictum vestibulum. Nulla non ullamcorper quam, sit amet luctus purus. Sed nec convallis urna. Aliquam erat nulla, maximus id nisi a, ullamcorper porttitor turpis. Aenean iaculis diam eget nisl scelerisque posuere. In sagittis nibh at congue viverra. Praesent eu commodo ligula. Suspendisse tristique a mauris eu ornare. Quisque et libero fringilla, condimentum ipsum id, malesuada nibh. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Fusce vestibulum iaculis luctus. Praesent consequat fermentum felis non dignissim. Donec neque sapien, viverra sit amet ex non, malesuada lacinia erat.Donec et dictum lectus, sed sollicitudin mauris. Pellentesque ac faucibus metus. Praesent nec dui a libero ullamcorper vulputate. Cras id nisi at arcu eleifend commodo. Curabitur iaculis, risus luctus luctus tincidunt, odio quam aliquet metus, at dapibus nibh nibh ullamcorper magna. Fusce eu nibh semper turpis suscipit scelerisque varius eget metus. Nullam posuere scelerisque mattis. Aliquam viverra euismod odio posuere aliquet. Phasellus rhoncus maximus lacus. Duis feugiat faucibus auctor. Aenean tempor aliquam ante eu blandit. Sed nisi risus, iaculis vel mauris at, pharetra euismod ex. Vestibulum id felis sed magna blandit vulputate. Ut interdum consequat placerat. Aliquam in arcu euismod, malesuada ante in, ultrices arcu. Morbi sagittis a sem quis luctus.Curabitur facilisis tempor enim vel pretium. Sed bibendum luctus libero id iaculis. Nulla bibendum tincidunt massa, sit amet venenatis arcu interdum a. Donec accumsan magna a mauris placerat, eu pellentesque est sollicitudin. Mauris ut sodales lectus, nec ultricies urna. Praesent in arcu sapien. Nunc commodo imperdiet arcu, sit amet lobortis massa. Maecenas vitae venenatis diam. Sed condimentum metus vel maximus porttitor. Aenean vehicula interdum lectus et venenatis. Sed pellentesque quis ipsum non auctor. Duis suscipit tempor diam, in consequat diam accumsan nec.Suspendisse a sapien eu elit ornare aliquet facilisis at ligula. Integer laoreet purus nec felis bibendum, id ullamcorper sem vestibulum. Nulla iaculis magna id nunc vestibulum, non molestie mi placerat. Etiam tempus augue in sollicitudin tristique. Nam in porttitor orci. Sed ullamcorper enim eu metus viverra, vel rutrum mauris aliquet. Duis malesuada congue mattis. Etiam at metus tristique massa viverra mattis nec id nunc. Vestibulum nec lorem dapibus, molestie elit id, ullamcorper turpis. Curabitur rhoncus aliquet aliquet. Aenean non ante dignissim massa cursus interdum. Pellentesque consequat nibh ipsum, et ornare nisl laoreet ut. Vestibulum lacinia ut augue at elementum. Donec fringilla tincidunt odio ut fringilla. Vivamus pharetra nunc vitae dui nullam.";

  protected BaseTestCase()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
             InvalidKeySpecException {
    _ellipticCurveKeyUtils = new EllipticCurveKeyUtil();
    _serverKeyPair = _ellipticCurveKeyUtils.loadECKeyPair(publicKeyX, publicKeyY, privateKeyS);;
    _clientPublicKey = _ellipticCurveKeyUtils.loadP256Dh(p256dh);;
  }
}