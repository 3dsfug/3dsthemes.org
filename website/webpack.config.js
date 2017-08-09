const webpack = require('webpack');
const ExtractTextPlugin = require('extract-text-webpack-plugin');
const UglifyJSPlugin = require('uglifyjs-webpack-plugin')
const path = require('path')
const cssPath = path.resolve(__dirname, './build/css/')
const jsPath = path.resolve(__dirname, './build/js')
module.exports = {
  entry: [
    './js/main.js', './web/css/custom.scss'
  ],
  devtool: "source-map",
  module: {
    rules: [
      {
        test: /\.scss$/,
        loader: ExtractTextPlugin.extract({
          use: [
            {
              loader: "css-loader?-url",
							options: {
								sourceMap: true
							}
            }, {
              loader: "sass-loader?-url",
              options: {
								sourceMap: true,
                outputStyle: "compact"
              }
            }
          ]
        })
      }, {
        test: /\.pug/,
        loader: 'pug-loader'
      }
    ]
  },
  plugins: [
    new ExtractTextPlugin({filename: '/css/[name].bundle.css'}),
    new UglifyJSPlugin()
  ],
  output: {
    path: __dirname + "/build/",
    filename: "./js/bundle.js"
  }
};
