const { defineConfig } = require('@vue/cli-service')
module.exports = defineConfig({
  chainWebpack: config => {
    config
      .plugin('html')
      .tap(args => {
        args[0].title = "GearSSH";
        return args;
      });
  },
  transpileDependencies: true,
});
