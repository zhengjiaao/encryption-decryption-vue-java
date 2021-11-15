import Vue from 'vue'
import Router from 'vue-router'
// import HelloWorld from '@/components/HelloWorld'
import VueRSAEncryptTest from '@/components/VueRSAEncryptTest'
import VueSM2EncryptTest from '@/components/VueSM2EncryptTest'

Vue.use(Router)

export default new Router({
  routes: [
    /*{
      path: '/',
      name: 'HelloWorld',
      component: HelloWorld
    }*/

    {
      path: '/rsa',
      name: 'VueRSAEncryptTest',
      component: VueRSAEncryptTest
    },{
      path: '/sm2',
      name: 'VueSM2EncryptTest',
      component: VueSM2EncryptTest
    },
  ]
})
