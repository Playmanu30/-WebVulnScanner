const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = (env, argv = {}) => {
  const isProduction = argv.mode === 'production';

  return {
    // Only the renderer is bundled. The Electron main process (src/main.js)
    // runs directly under Node and must not end up in a browser bundle.
    entry: './src/ui/renderer.jsx',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: isProduction ? 'bundle.[contenthash].js' : 'bundle.js',
      clean: true,
      globalObject: 'this'
    },
    resolve: {
      extensions: ['.js', '.jsx']
    },
    module: {
      rules: [
        {
          test: /\.(js|jsx)$/,
          exclude: /node_modules/,
          use: 'babel-loader'
        }
      ]
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/ui/public/index.html',
        filename: 'index.html'
      })
    ],
    devtool: isProduction ? false : 'source-map',
    performance: { hints: false },
    stats: 'minimal'
  };
};
