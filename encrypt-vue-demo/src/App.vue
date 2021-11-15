<template>
  <div id="app">
    <!--    <img src="./assets/logo.png">-->
    <!--    <router-view/>-->

    <H3>前端加解密-示例</H3>
    <!-- <router-link> 默认会被渲染成一个 `<a>` 标签 -->
    <router-link to="/rsa">RSA 算法</router-link>&emsp;
    <router-link to="/sm2">国密算法-SM2</router-link>&emsp;
    <router-view/>
  </div>
</template>

<script>
  export default {
    name: 'App'
  }
</script>

<style>
  #app {
    font-family: 'Avenir', Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-align: center;
    color: #2c3e50;
    margin-top: 60px;
  }
</style>
