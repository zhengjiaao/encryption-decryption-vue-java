<template>
  <div class="hello" id="app">
    <h1>{{ title }}</h1>

    <el-input style="width: auto"
              placeholder="请输入待加密的 明文字符串"
              v-model="plaintextData"
              clearable>
    </el-input>

    <el-button type="primary" @click="clickTest()">点击尝试-加解密</el-button>

    <p>加密后数据：{{encryptData}}</p>
    <p>解密后数据：{{decryptData}}</p>

  </div>
</template>

<script>
  const sm2 = require('sm-crypto').sm2;
  const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3，默认为1

  export default {
    name: "VueSM2EncryptTest",
    data() {
      return {
        title: "演示国密算法-SM2-加解密",
        data: '',
        plaintextData: 'pass123',
        encryptData: '',
        decryptData: '',
      };
    },
    methods: {
      clickTest: function () {
        //明文
        // let plaintextData = "pass123";

        let keypair = sm2.generateKeyPairHex();

        // let publicKey = keypair.publicKey;    // 公钥
        // let privateKey = keypair.privateKey;  // 私钥

        //密钥对-前端生成 前后端都可用
        let publicKey = "04c0a90dc19469d0e842bb6e47546951e5827c959476f87299e03152fda52e4ba44a84bcfe797586db444715a00f45007c01f26db0cdf807e85a88ac5c86ebbeff";
        let privateKey = "0e0993a5e7d9584cb78e44cd0f74b0eb21614aa8dddf54893df466097b4b4233";

        // console.log("publicKey: " + publicKey);
        // console.log("privateKey: " + privateKey);


        //十六进制 密钥对-后台生成 后台可用,前端不可用  前端公钥需 04 开头
        let hexPrivateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104200b0b37873f5d940aa4a6da744dd7080849b1bbde408b174c3b06b5e23963ef5ea00a06082a811ccf5501822da144034200049edae0afb36df29b2dd354e98bca3031d3deb157b8a287dcb669d27e7d4264694b5683b26bb47aa503812dd1af8bf54d42b2a2bc040c8b7f228dd111b6b2ec71"; // 私钥
        let hexPublicKey = "3059301306072a8648ce3d020106082a811ccf5501822d034200049edae0afb36df29b2dd354e98bca3031d3deb157b8a287dcb669d27e7d4264694b5683b26bb47aa503812dd1af8bf54d42b2a2bc040c8b7f228dd111b6b2ec71";

        //base64 密钥对-后台生成 后台可用,前端不可用  前端公钥需 04 开头
        let base64PrivateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgCws3hz9dlAqkptp0TdcICEmxu95AixdMOwa14jlj716gCgYIKoEcz1UBgi2hRANCAASe2uCvs23ymy3TVOmLyjAx096xV7iih9y2adJ+fUJkaUtWg7JrtHqlA4Et0a+L9U1CsqK8BAyLfyKN0RG2suxx";
        let base64PublicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEntrgr7Nt8pst01Tpi8owMdPesVe4oofctmnSfn1CZGlLVoOya7R6pQOBLdGvi/VNQrKivAQMi38ijdERtrLscQ==";

        // let publicKey2 = Base64.decode(base64PublicKey);
        // console.log("publicKey2: " + publicKey2);

        //十六进制公钥串(0x04)  密钥对-后台生成 前后端都可用
        //获取65字节非压缩缩的十六进制公钥串(0x04)
        /* let publicKeyHex ="04fc60c8396bbc4627b93660c7375d671b5d157f61d4322021c62ca40fa145b12dea5e5b24b1873d81f165c5ec7f71245e78ea8ace9f5073b11d195ceecc8f3c6e";
         //获取32字节十六进制私钥串
         let privateKeyHex = "1a8122ff166aea713af503eea2ffed952a4703377388d4e717ad8c7e3a29786d";*/

        //十六进制公钥串(0x04)  密钥对-后台生成 前后端都可用
        //获取65字节非压缩缩的十六进制公钥串(0x04)
        let publicKeyHex = "04a750962616733abeb58084f0ffab930f3bd34236bfad82f31e8bc5567f77c0d633e2e62f064e5a00a44e530bd7a37e32d48909464de03c27e9a2b1f625907ef2";
        //获取32字节十六进制私钥串
        let privateKeyHex = "11c1420e5368d9b164451979a0f667105dfb9917fd810d8f1016106feefde535";

        //公钥加密
        let doEncrypt = sm2.doEncrypt(this.plaintextData, publicKeyHex, cipherMode);
        console.log("doDecrypt: " + doEncrypt);
        this.encryptData = doEncrypt;

        //私钥解密
        let doDecrypt = sm2.doDecrypt(doEncrypt, privateKeyHex, cipherMode);
        console.log("doDecrypt: " + doDecrypt);
        this.decryptData = doDecrypt;
      }
    },
  };
</script>

<style scoped>
</style>
