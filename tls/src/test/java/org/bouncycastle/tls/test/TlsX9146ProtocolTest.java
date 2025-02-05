package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.jcajce.provider.Dilithium;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class TlsX9146ProtocolTest
    extends TestCase
{
    public void testCustomVerifier() throws CryptoException
    {
        byte[] data = Hex.decode("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c20736572766572204365727469666963617465566572696679005fb07468bb7bab7a0a26175cdcd04b51a227ac93fdb68c919b83fe446f0b8f2b");
        byte[] signature = Hex.decode("c1dbd69b6fa98212643c89f876db4aad16f4141fa25e059e2e3a4900a622198a8fcb5fcaa321003c5cb032b0d79ca5c4d4025b202292f4c1f22f5772069270b2e1c19a37d64a15c7b2f0fee7f4a9fad5a1d1f09f1f7b7f49536daf2b4c3bfb0bd0582a7ba424a5bb69d5d786b38fc3bf9a11b8126f356656f2ab980dd2ceab64ef350710db7d7f916b22d45d09a29aa3c566065ea1f530ba77276f080c41c336caf28f115544cc6c945b32cac8c0ea73e395abae005eab10ef1675b2c3a5be81dc1a44e10e2ef2bd0ddc5f24a0112bed14675825ee40b906331d33dc8bf6ed27722ca5ed333602f057cc94548f5928ee3dcbc5dadaa9b84554a14a2708e2fb3adc31dc74da4c6a7d91ac3348101f33ffe67426710f7e3c761d285a457a71ee93c49dcc7a6641a930fa6aa0381bf06968b521da2968525051d25a02f85f9ac09147e9caf20f1341fc3d5c00249be268e22a54d90a56db6bb7202187fd961cb9cdde0c3ae7cf5392bf43c802e8ea3061b821d11d2a952f4e0b9596d945f4aaa923e988f793a74bc8c3ee92476c32040da4ea64356c05b2127bd9ccc840262103a81e4e34bebc7b71e31efb1a944daece8aa8a793192244375894b9926ea6928d076a5775886dcca55e91d84d42929ffcf3bf2c718dccd12335dd31b8125f3738bd92ab90cab1c265aa84257b2e45840a5449b061d5bcb27d32b8354cc05c4c3ddd9dbd21cf859461acc6509a392857ea920e86018df70e53addd4bafa6f5480707b76e0e487c5e1b3281b9a3ca23d2f21e304c8ac778d14b67b0ef0e076035429bd16b22c39ad3346376bbc1e715a6896ac8795cf02fe8bac7192e06ae41e703e620e479c28dd55eb5732ee969d7e8405f17e76c8864a7aa79ff7c21b181709690f497f98fe68dd9555154b71f7d8fc5f3f8cd0e4d350ce8b737ac968c227a40d39b28596fa675c3add386edd4a5d5ca5ea5cf7f409b91b6e5413b1c40b08bdc8622624ddc63bd724c18879c5fb0e94b72b7df80ce875e8e827122a82d3c8050743eb94b8df7347245d5f3ffc7a289ba0db8d58176734f770028f072bea98e1b37d989ec6566d1bc9ce02ffd4ff27e313b1965d55aff04721de9a13261c6ba656022c21ceb54ff2641b78dc3782142f62af1b57f0ec73033e72e8b7db860a916848742db10fc7ec6365f6a9c852d0a62837dbaae385dda191d42c7183e59564321ea834d805ae0628d107ab29545916024af1196eb940ee45f89639504544c2e629079500861cd77dc9fd57efc8a1d0435710328e2779ca8c3596ad4bb77c06bf0cc4eea0c535a3ddca4d6c9a0c5aa3835ad197a2eb19157992060129c381f72b04ec866c0f9863d9e6ff08a1c115af4b684fccd9114787d517e62666c0d0b741599955063a3dd508434a3f395d0de6cb60b7b69bab1956de73d168937d7fc6c6af1d6b670ef6b93f4df114bf11fb63defcb16331b71164f32ff78c3c1705d85ec187da0049042f87dff92792c58bed3d1143bd9f9c758b219891c291552ebfa013a9fcfe39131dc79ad5020837e0de37807bfe25eb2a01dce6c1102d6991c323860ea481f57dc521eb558d2d7876162e3163429512eca464c590a73ff4c6d5e9a403750294503955044d7a3b45dc5adde81bb61000c5376e6e24dcd1ff296ea0f12f45e204ba01551c0232d39035fdf186e2264b232c21ae69768546cfc3921aaee9ee3289e4e8ed4c6b87cc1a46e5081c9846782982d481490e381be6174f30ad1e137db076e9a07fe30ea2942562b4b93979414eae4eb5df5106a5a9201f6229be7f3123bd4fb289a1f8f3875e67183d5feaec7b844d891c49086c00929457f22d2d52214b16a1a28931130c8a0a93d75cfa092476f2b01dec57a8d98a938a771b3893b926352967d7ac3c30bb929bcc9792997e56e6ef0f22d1a26fc0f45425bcad36a2a4b6bc45c16611970443561e12426e0983f7fc15dcc11c2c4b9e2b9dababe671399bb3f0e5f83e19ad013c95ea1bb14f1ee78f4d7b93961331882df13fb9d7329a49bc4b92c0e0d95f4716c1927aaa57a4ef5f4dea4e4a9076a54360675de35cb8d2526c1cca8c90d04fa148bc3369b538f06bd41b86ca03f48823f37435f315989b861b5aa788432c156918c9b24637286fb8aafc81bdccf1cd9ba0a1430f4df82b1938f648127018ccd4f0642ed3c07dba00744b0641cb8a06ee9ed46cdf6d91b9f2dd29c172b7b0b687d344d4cf76a7aa7f35a3cf45b5dea51be6431db25a9d7656ddb8a4ba73599b4228f58c9c05118bfe832fc7dc24da7e349fb8fa80048546cd63ed002a210890de8a1d1cbffc2ff2edb928f7c0b6c77c48266940827d7da0d4e2a7ef2e348a1bd2a4bedbeb3e5ccf632c4cdcc17ef197f25fd9ac13bebbf8db75ff4a5d9dcbc9a6ed6aa4448812d3a7e6a8519f41ee9c865c49379a29edd3cd274f81d58d3ea85afe30f214492aa0a04c2af720d6b1f7c60b904ffb63444b58b6026f0660ade13336c5a0ceeeb4603f797d6c81e0edc7b35ad465d9046dfde1687eb3a16fe74fb4b59e13fbfa8626f499b31a96770b07e09083b6be7889385149ceccfd786b7fd6a7321779c947aa3e4f7533e7b03564a7d94f441efff88069b82434254ad275f7fa8be60cf5934b05aa4061c5ccce75d5d6b0f80bf61bcaa8ede0a79ed49c27015e2c037826f838303dad15394ce7d13baadf2550bd925b982d0891223a681f70eca11d7f943b0cbad4186ada02e1f37ace5aca0575bdfae30edad648c4058ff70ca97c4f13b011d2ecabfc391fdd33147dc40976334e1fac42f50f27cf4da43af982191e1cb7acecbc0cc48576510cc8542e44996eff72fd5d89705def1b0c3c7837cde93677479ce471eea98c4049f6285dfd9275cc4c695a2154247668975af04a11030f48067b849b7477df81b59358f7ef6615192fb94b9dabbde0b6c7e74bba33c21135d57fc576f7a5274e3f34c928d51ae88e7fb0f869cde03c15322659c71ed70e2da698fbe525b016395b5e7a6785abe08b7c966f77977b24c3176169be03e927cb119047156ddaa2f4c081cbd2b7ff439006685e82a0333f350c5465f55818a146466cc90b847d82330956e254b4ef34c0451608705db915b3d1c6fbdab58c4f3a35c757cc14fbc242a38237514f8648e5d5a85bbcdce7c6ba9bc0c5e75dc1b14e9ef9143333842d72ee39cc5c0112908ccb0fbceac1a56ac07d372a3dc05a128781d263ecaa44e6a57897dd909734428bfe9685871054a3e473762754925b4632bf6e5e14baca8bc8b4f54182934558893a0aab5bcc1fbfc0c141f314e879199a2d6dbe2eaecfd0f18203c3e557075a1a4a7b6bbc6d5e2032a4f5375768689b4ccd9dde000000000000000000000000000000000000000000000000d1c2c39");
        byte[] privKey = Hex.decode("30820f38020100300b060960864801650304031104820f2404820f20676dae39217942e34bb9c825ebbdce290523d707f734c1b63b2cccae33cd066af25bbeb0c414fa0c01571e780e40ab131267e098541d459fe249a4ece4fd8544854af30a5ea809176adebba103ed54fae10c2d0058c237a94df5762854e9177ce70f151e40b602d5ff4b24fc79dfe2782fcea21919fcb8eeda2439695dea544a0301221bc26960a608e0025143c44c9038211102444a842419c22c0ab22d24996cca460909a0480bb74100c8041b196ecac220238850402889dc46202111098336321b182d984845d1a480223446003471a2284e221785d434629b366da1440602a30d44426063c684888664033106c128011c1745d284689c1422da4281c980115818010b165218a44123286e1a824c00142d13a5118040704aa260030740183640041066d4022280b4088b304c11c62dc4c06c23486124184448368558006a09378023b3491a4284a0340a1b31851c90518a12725490090114841b8745134911642600084691820032a42248e3b46c230492401010db2046022745c3366244406a4c8600cc2452db80245a3604230404e0844d14304801c92d42c85020c62852a02c9c10401840401bb36d211265200586a3a251580642dc128499420e4b00704910511a083112234600366418030493982de0968d12a0098b384a12b9299ca01022892d0c290ed0148609483260a08c19a33062a068c814851b15001022641a2368a10842110811a4c0319006445c90211881910c818c203640882440d3a684d0a86d5ac04444046049462e10050e4ca2298ca8212103606442090cb725dc344a04302c02b08189804d6046865a248d1b3649e4402d18a32018062a5ac82512068e2246840c3991c4984411335200194a64b26909a66c19170d51882c23026a5a048614b16cc8486a42126922a070d1b42561b66409a78919462140c84152000012152ec4162491144c22a588c2c87089802c0836208cc6859110411c4151d982506422292433904c184c00986019310a603468dab4440449244b3042da180e18250e1ba945ca42002110269a904093068a242429c8a0881b932863c201643488e4944161480e4b266d5cc44c03c90d1a93041104220996251c3705e034509a100d8c066e0934120344065bc28514b12d0c114d5b36685a4411403420091965ccb82008806d8ac408422820a4026e52a08ce0b4648cb2305142229b2690610281cb289250c82d9c4022410091d1c450023966911881da28894c288848b801e8cde89174c89feab7e0d7383e8e64a363accf374d3801dc920fc56d51ad9109e445884b4a12d341e44f02b939337e3a2a68283939265ef485ad390d07af233f405066397453a48c2c525b193d335a7e107eb973aaff7805356d3242243a3bd5fd300ebec17f2430535f1c7f6ace928e517c1d862be3732908fcaddea657f6207a4be1259808ba075125f647b2f36f397d4cf0243785b95c8a13f6bb77d4f3d5eb04cbb23a8bb58e2f98647c5896587877cf32a72cf2733a06a0c1dace34859d0f764d15f694d145d53445005e25734e19bc2e501118daaf4f7a93efe8830d5d7598deb1aef50eb94224c784d2104387ffff23de623558691edd234d7a1255a830505cf9ffd732e14d0dd641d990ef829c006a6bc56bb18ad674c47a27ed363651c7ec11a60031b24142a305e463e675bc757325fdef1837967b0df4634e6f4b6a87bb13daa6e0adfbfbfb2f20fc8f85e227f3cfa3631d4e2f86a1617793ed45b889925398d76fbd20610c67e2282e2a8a1bb6543c51a323cae22074759ccf78f64a2d417a6e16329623b578ed99d3c0c5fbe30ad11b5737ffdbaa230db36798ebd1afe5c949c563731781693136e88a189497cef64026058922da649ad3de2f616e01c2190436d7dfb468774b3f58306bf3601a1613e240c7e9811e0fbe0d092d79df64151c1cbdf51c3602cfa02b663a6b15f03b65ded28bd27bb00429c101c9e08de4f0fe5f9aa590903a1e3410c66642bdb231f9a6a0fcd517737fb75e4edb6da382b61d6f50d6ac224c527f5757301835fd09517daaa7a2f4e01b957e3f5676f6b6884e6ad4ed92e7ff5a9c1f56a5d85b1243de9dd08be595fa4b2e654623002cf326154f9710cb890f3ac23c99c1b4d61c963760c761b1e028bfe48cacd30dad9a13204bff01cbaab43759069496a71c8db988d754acc1dbb8c6fbc67e566e9f2bf38a0a7e36c6da0912aec3bf37e1724d853312a6fff8d834bae939bb99913ea365911d08631f4d70c54f8589d76efa4bfe713ef2c7b533d24b9584152a67f4c587e6cad58e169ba3d93dd821d73f3753ea626c057486dd0c262453331a0867171c2be4f49b7254fcaa337ebc50d3fb8ad61547f215918eea7d80f1a14281ae4f7d631efd1dfd19d7897505a8f776b0c15c0563f0d62eb1acee9c7662003450597f1ac64efe270a5dcc60f5ec5a8cf7a92521f5b20f6f5b4be7fc21453df129a9e8e51b29bae88e47c3393b27dfa66698cff5d08d0914cbcabdccc700f77d33a76b473aa09de78b5f4f02ad0a4aacfbc657b5a875656249930b1b77a3d82cc4c04c99321aa2917a18b2559bc29050145addcd1a06e9f3830e808e322944e1bed6e79bd75a3df76bb7557384b6d96dac92d9b3619512da9162b0b3c28a674fe2641001ff11ef85bb68195850a3f5befb322c01163f57657ee694046c5abdd15e4df41ee9158f3e316135e8395760f93604018a25efd1309b469a810ff8231c0840d323e38970e53023e0a6e467dfabae27959b2727137d3cd6b6d5ca202c5c61d63645959ad6e3e38790336b2bfd85370b880aeb2a23a6db2361adf080a83b01609587564b7eb1e02151ab60e9c9f33241bc74a4250f65a3deed12a66e7461bca26f686b21f10122ee6667af11b244175ec9b4d3d00a25b3047211509188ff514bdcce6de8f383f44726d04ea44326e347c969865dbaf441b1ad45941d28aa5c959ca2f122cf882698edb010b60a3f28303c7ddc0a659f359c2d6772563c0c58f54502f3af3542f96e054a459f6936325c86dfd66a4374717cc196a06cfe4272685cca5ac4c9a69b65ba9b76a477c04aa178e0755118fb21bdf47debb8087d6e23bb0ede0e0ff9824df9d0c93b3ccd359dc3df6436a449e7fc36497cc67e6b3807bd36b5846edd9c013a9e4b8b8fa087d99b49e6f93910cf9bcba1cd330310278de4d8f8b7848d933b31f4bab2a43ed00689cdf9434238ba85c2592835b21648cee156b1c006f1e1645a622f8c8dea13da327a7614c409f52bd1d6c586c7cfa22e5e3997882562cfbaf5158b0f68485511e2427c776d663adfd7fb5edacdc43472ccb43e24b80c18e69cf05a1b7b1152ac19a495c495bf94373016b1052ac7721cf79546bb0d2be020f38c627ab31a8dba6583ca74369bc6e2f1e9b53151c85f6b8e8b782599eacd036d275b709cc135f9ba1a961d97b6d791640d7f1188c33ee3468b1fa85db0a40dcf45d7b83821d775be72a0aec8b37a0d38f285718aa3fd5d04e7503d8d00f74614ebfbfdde864e163c96f68194d202d45cc1edeb17bde74b1ac3f4be36bb83e8375a68cf75293000a0af24356eaec1000efebd0a676dae39217942e34bb9c825ebbdce290523d707f734c1b63b2cccae33cd066aebd3da7dca4e02fd09a092741dd5bba52384da84b898642f99ce4b9e3d429a75fa1e835e65ae6ae9b713bc82a17367ce8b8b4a012ed40ec470eb404c174fb65771abcbcab887845e528e49d045ba3c755ce5e7ffef8436f9ca7929183d22441033f1b8a6eb288fa450e0326386be686346f4aab360eef49b773a5d1616923b52501d1e7fa087f7da3318fa0bea822b0397ffa0e90b02b29689bc26d3dd89be07d816474ec2bcfa851ae2cd9e130b56a49528f824b436b2482faf8afb1255c9c7ec9a8ebddb799bd6aca33646621fb4d7edfc6c9c65c1d44ad0305d9ad8dd319d3cf3d097d441bb2ccbecd2257302cc0247377d9ef9a7794d046ddd39d71be5c1853baed99aa4e02caec7d5b612cec59518deb2e127deff263e1f63cdaedeceded67c94a6b2945f7fb7b88d0b5b6fc08e2bbb4c7c85a67f38d7900345a5aecebde0ee070d4bf5969ac814e5efb41fa4368861fb1c72549523496f698a0182e8abe71e33eea97ab32a1bdd2a22dce7e474b747e8a86e4db5fbd15282669d91153d7209cfe7e18914c9f38c3c3ab28bc8270648a5377502ce00af151aa544e219bdd57b807deb80306d1d3755c0bba0d28d394f3eca68a822dabd92e69d318cf8c92d55515234a6769c9a7193b68f0336c36e4a981bb28b4fdb23b9c127cada02eb5ede6f5dc0d989fe18b9abe5e90a5f67239118a267f8ed6e9807bc1c8fc0b33565ea5459d6dc04f412210a9fd000362216159dd07942df699586d8a1e6933dfe61340c9b346e0b84dc88a94a1651d1689c6c3dfa939451f6a50fc51ea733683c09fb300a58655fa739fd84c182de2112dd0c0dfc93897070db6428f7289b13cb11b63c967fbb76fafdfbed7503721d7b5b8952af11546b371ea29b7951bfa145355ac6d88fbb1a36ae644fc8d8f8141ab46250fc1576234841ea0ba97aa35a9a1fa0a5b005c8f4c7cb76c6838290940ad1b28825cd955a0c526dbe2d35528d87655f2b56439abaca5bb047419b33140b1fbf321da7eb5d1acd47efdb85d08ccf5ae075c3b0ac219843763e372af92cf35349af7b1bd44f3495fbc6246bc47c6fe68c36b219a669561424f971cb687128851d349c262afbe63739e7b7c1db85e49cf1d96e0533e74b34707f72901ead0e5e765c3b41d9b9b8736e827a6539f457da529c7d481bc3b17bf824d7c62394201aef31a02a37a94bb1ae06262bdeab9d25c5373ef00c93aecd6c24b6e651e4f929e854d9bb1f91bcc245b251de592a25351ba295627fca3ec472a14e2c5b04a008a9ed9a553406fcb35cd76f23420b55545d258f481818f89a0e58bea5212964e0eaf67cd66e4ea7f918f59b69e0e2cc2c382b7c32132f755c68501172d6372b43e31572112e48e48028a34ef73d2e4d4cc36e052ce53aec0cf1d8e6153b549b7e835b28e885c6c9f253ecb3a9065b389f9627095def595b67593e5a5ca4f946ea15e61991e1f67986d1fd5e80e349e960b879635bafb318082ee9e13c436618dfee51e1a9d152a74cd15114a60f1472c1602cdf6083a64a64d5f7f3500222c9dbc1b95af643a43e3793ff8d3a26a696f27dbc8efdcd61fc1483283205c5b0af149cab8d90ac5f5e96e36e8fa38986aca632292b45b87a4e5df71aac7cfe4093c1a7394b71abae2fb1cddae73ee4957494c123c4a4e5816e834d5b2c291a250e0fe344768911b50c34e2dd9eb04ca5fdb2a1e71763bd07fcb13529acacce9967a08eaaabea216b9f655ca0ae0c046ff8fb580b3c9af4d353f18e4fc993fcfc20dee6178db7cd3e3c4e2a2cf557816ac5");

        DilithiumPrivateKeyParameters dsk = new DilithiumPrivateKeyParameters(DilithiumParameters.dilithium2, privKey, null);
        DilithiumSigner dilithiumSigner = new DilithiumSigner();
        dilithiumSigner.init(true, dsk);
        byte[] dSig = dilithiumSigner.generateSignature(data);

        MLDSAPrivateKeyParameters msk = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, privKey);
        MLDSASigner mldsaSigner = new MLDSASigner();
        mldsaSigner.init(true, msk);
        mldsaSigner.update(data, 0, data.length);
        byte[] mSig = mldsaSigner.generateSignature();

        //TODO: check if any of the dilithium/mldsa signers work with wolfssl
        System.out.println("d sig : " + Hex.toHexString(dSig));
        System.out.println("m sig : " + Hex.toHexString(mSig));
        System.out.println("e sig : " + Hex.toHexString(signature));
    }
    static TlsClientProtocol openTlsConnection(String address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        System.out.println(s.getPort());
        System.out.println(s.getInetAddress());
        System.out.println(s.getLocalAddress());
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);
        return protocol;
    }
    public void testClientWithWolfServer() throws Exception
    {
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();


        // hash:  0xFE (254)
        // sig:   0xA0 (160)


        MockX9146TlsClient client = new MockX9146TlsClient(null);
//        client.setCksCode(CertificateKeySelectionType.cks_default);
//        client.setCksCode(CertificateKeySelectionType.cks_native);
//        client.setCksCode(CertificateKeySelectionType.cks_alternate);
        client.setCksCode(CertificateKeySelectionType.cks_both);

        TlsClientProtocol clientProtocol = openTlsConnection("127.0.0.1", 11111, client);

        // Adds the CKS Code to the Hello Message

//        clientProtocol.connect(client);

        byte[] data = "hello wolfssl!".getBytes();
//        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echoBuf = new byte[1000];
        int count = Streams.readFully(clientProtocol.getInputStream(), echoBuf);
        byte[] echo = Arrays.copyOf(echoBuf, count);

        System.out.println("data: " + Hex.toHexString(data));
        System.out.println("echo: " + Hex.toHexString(echo));


        assertTrue(Arrays.areEqual("I hear you fa shizzle!".getBytes(), echo));

        output.close();

    }


    public void testServerWithWolfClient() throws Exception
    {
        ServerSocket ss = new ServerSocket(11111);
    
        System.out.println("ServerSocket port: " + ss.getLocalPort());
        System.out.println("ServerSocket ip: " + ss.getInetAddress());
    
        try {
            Socket s = ss.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
            try {
                tlsServerProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                MockX9146TlsServer server = new MockX9146TlsServer();
                server.setCksCode(1);
                tlsServerProtocol.accept(server);
            } finally {
                tlsServerProtocol.close();
                s.close();
            }
        } finally {
            ss.close();
        }
    }

    public void testClientServer() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);

        // Adds the CKS Code to the Hello Message
//        client.setCksCode(CertificateKeySelectionType.cks_default);
//        client.setCksCode(CertificateKeySelectionType.cks_native);
//        client.setCksCode(CertificateKeySelectionType.cks_alternate);
        client.setCksCode(CertificateKeySelectionType.cks_both);

        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockX9146TlsServer server = new MockX9146TlsServer();
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
            }
        }
    }
}
